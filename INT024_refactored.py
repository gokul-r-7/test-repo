
import os
import re
import time
import json
import uuid
import base64
import boto3
import requests
import pandas as pd
import numpy as np
from io import StringIO
from datetime import datetime
from urllib.parse import urlencode
from integration_helper.logger import get_logger
from integration_helper.aws import DynamoDB, get_secret, update_secret
from integration_helper.constants import REGION
from integration_helper.jwt_auth_token import create_token, validate_jwt_token


REGION = "us-east-1"
# Logger setup
logger = get_logger(__name__)

S3_BUCKET = 'worley-integrattion-work'
S3_KEY = 'INT024_source_files/Sample_file_INT24_test.csv'
FAILED_LOG_KEY = "INT024/error_report.csv"
metadata_table_name = 'sydney-int-mf-stg-metadata-table'
primary_keys = 'INT024_TEST_DATA'
input_keys = 'INT024_TEST_DATA'
POST_URL_fail = 'https://reqres.in/api/users' 
POST_URL_pass = "https://eol99qtwfxfpjp.m.pipedream.net"
host_url = "emzo-dev1.fa.us6.oraclecloud.com"
workers_endpoint = "/hcmRestApi/resources/11.13.18.05/workers"
salaries_endpoint = "/hcmRestApi/resources/11.13.18.05/salaries"
workers_query_param = {}
salaries_query_param = {}
api_timeout = 30


# DynamoDB setup and metadata fetching
ddb = DynamoDB(metadata_table_name=metadata_table_name, default_region=REGION)
metadata = ddb.get_metadata_from_ddb(
    source_system_id=primary_keys, metadata_type=input_keys
)


auth_info = metadata['auth_api_parameter']
print("Auth API Parameter:", auth_info)
workers_payload_json = metadata['workers_payload_json']
print("Workers Payload JSON:", workers_payload_json)
salaries_payload_json = metadata['salaries_payload_json']
print("Salaries Payload JSON:", salaries_payload_json)
field_transformations = metadata['field_transformations']
print("Field Transformations:", field_transformations)
conditional_field_rules = metadata['conditional_field_rules']
print("Conditional Field Rules:", conditional_field_rules)
pre_validation_rules = metadata['pre_validation_rules']
print("Pre-validation Rules:", pre_validation_rules)
lookup_rules = metadata['lookup_rules']
print("Lookup Rules:", lookup_rules)










# ----------------- Helper: JWT Authentication ----------------- #
def get_valid_jwt_token(authentication_info, host_url):
    """
    Retrieves a valid JWT token. If a valid cached token exists, reuse it;
    otherwise, generate a new one, cache it, and return it.

    :param authentication_info: Dict containing keys for secrets and token config
    :param host_url: The HCM host URL
    :return: A valid JWT token or None
    """
    try:
        jwt_secret_key_name = authentication_info.get('auth_jwt_token_key')
        cached_jwt_token = get_secret(jwt_secret_key_name, REGION)

        if cached_jwt_token:
            token_payload = validate_jwt_token(cached_jwt_token)

            if token_payload:
                token_expiry = token_payload.get('exp')
                audience_url_count = token_payload.get('aud').count('https://')

                if int(time.time()) < token_expiry and audience_url_count == 1:
                    logger.info("Reusing valid cached JWT token.")
                    return cached_jwt_token

        # If token is missing or expired, generate a new one
        secret_credentials = json.loads(get_secret(authentication_info['secret_credentials'], REGION))
        username = secret_credentials.get("username")

        certificate = get_secret(authentication_info['auth_certificate_key'], REGION)
        private_key_b64 = get_secret(authentication_info['auth_private_key'], REGION).encode('ascii')
        private_key_der = base64.b64decode(private_key_b64)

        expiry_seconds = authentication_info.get('auth_expire')

        new_jwt_token = create_token(
            private_key_der,
            expiry_seconds,
            certificate_info=certificate,
            host_url=host_url,
            username=username,
            auth_info=authentication_info
        )

        update_secret(secret_name=jwt_secret_key_name, region_name=REGION, secret_value=new_jwt_token)
        logger.info("Generated and stored new JWT token.")
        return new_jwt_token

    except Exception as error:
        logger.error(f"JWT Auth Error: {error}")
        return None


# ----------------- Generic GET Request to HCM API ----------------- #
def call_hcm_api_get(resource_path: str, query_params: dict, jwt_token=None):
    """
    Makes a GET request to the HCM API using basic authentication.

    :param resource_path: The resource path of the API (e.g., "/users")
    :param query_params: Dictionary of query parameters
    :param jwt_token: Optional JWT token (not used in current implementation)
    :return: A dictionary with response status, headers, and body
    """
    try:
        # Clean resource path
        if not resource_path.startswith("/"):
            resource_path = "/" + resource_path
        resource_path = resource_path.replace("//", "/")

        # Build full readable URL for logging
        full_readable_url = f"https://{host_url}{resource_path}?" + "&".join([f"{k}={v}" for k, v in query_params.items()])

        request_url = f"https://{host_url}{resource_path}"

        headers = {
            "REST-Framework-Version": "2",
            # "Authorization": f"Bearer {jwt_token}",  # Uncomment when switching to JWT
        }

        username = "integration.user"
        password = "WorleyCloud@2023#"

        # Log request metadata
        logger.info("Initiating GET request to HCM service.")
        logger.info("Request URL (readable): %s", full_readable_url)
        logger.info("Query parameters: %s", query_params)
        logger.info("Request headers: %s", headers)

        response = requests.get(
            url=request_url,
            auth=(username, password),
            headers=headers,
            params=query_params,
            timeout=api_timeout
        )

        logger.info("HCM GET response status: %d", response.status_code)

        content_type = response.headers.get("Content-Type", "")
        response_body = (
            response.json() if content_type.startswith("application/json") else response.text
        )

        return {
            "statusCode": response.status_code,
            "headers": dict(response.headers),
            "body": response_body
        }

    except Exception as error:
        logger.error("Error during GET request to HCM: %s", str(error))
        return {
            "statusCode": 500,
            "body": {"error": str(error)}
        }


# ----------------- Generic POST Request to HCM API ----------------- #
def call_hcm_api_post(resource_path, query_params, request_body, jwt_token, base_url):
    """
    Makes a POST request to the HCM API using basic authentication.

    :param resource_path: The resource endpoint (e.g., "/employees/add")
    :param query_params: Dictionary of URL query parameters
    :param request_body: Payload to be sent in the POST request
    :param jwt_token: Optional JWT token (not used in current implementation)
    :param base_url: Host base URL
    :return: A dictionary with response status, headers, and body
    """
    try:
        full_url = f"https://{base_url}{resource_path}"
        encoded_query = urlencode(query_params)
        full_readable_url = f"{full_url}?{encoded_query}"

        headers = {
            # "Authorization": f"Bearer {jwt_token}",  # Uncomment when using JWT
            "Content-Type": "application/json"
        }

        username = "integration.user"
        password = "WorleyCloud@2023#"

        # Log request details
        logger.info("Initiating POST request to HCM service.")
        logger.info("Request URL: %s", full_readable_url)
        logger.info("Query Parameters: %s", query_params)
        logger.info("Headers: %s", headers)
        logger.info("POST Payload (formatted):\n%s", json.dumps(request_body, indent=2))

        response = requests.post(
            url=full_url,
            headers=headers,
            auth=(username, password),
            params=query_params,
            json=request_body,
            timeout=api_timeout
        )

        logger.info("HCM POST response status: %d", response.status_code)

        return {
            "statusCode": response.status_code,
            "headers": dict(response.headers),
            "body": response.text
        }

    except Exception as error:
        status_code = getattr(error.response, "status_code", 500)
        logger.error("Error during POST request to HCM: %s", str(error))
        return {
            "statusCode": status_code,
            "body": json.dumps({"error": str(error)})
        }




def read_csv_from_s3(bucket_name, object_key):
    """
    Reads a CSV file from an AWS S3 bucket, loads it into a pandas DataFrame,
    and performs data cleaning operations including:
      - Replacing string representations of 'NaN' with pd.NA
      - Converting numpy NaN values to pd.NA
      - Converting columns to appropriate nullable pandas types
      - Converting all columns to nullable string dtype

    :param bucket_name: Name of the S3 bucket
    :param object_key: Object key (file path) in the S3 bucket
    :return: Cleaned pandas DataFrame
    """
    try:
        logger.info(f"Fetching CSV file from S3 - Bucket: '{bucket_name}', Key: '{object_key}'")

        # Step 1: Connect to S3 and read the CSV file content
        s3_client = boto3.client('s3')
        s3_response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
        csv_content = s3_response['Body'].read().decode('utf-8')
        logger.info("CSV file successfully retrieved from S3.")

        # Step 2: Load CSV into pandas DataFrame
        data_frame = pd.read_csv(StringIO(csv_content))
        logger.info("CSV content loaded into pandas DataFrame.")

        # Optional display settings (for dev debugging only)
        pd.set_option('display.max_columns', None)
        pd.set_option('display.max_colwidth', None)

        # Step 3: Replace common string 'NaN' variants with pd.NA
        string_nan_variants = ['nan', 'NaN', 'NAN']
        data_frame.replace(string_nan_variants, pd.NA, inplace=True)
        logger.info("Replaced string representations of NaN with pd.NA.")

        # Step 4: Convert numpy NaN values to pd.NA
        data_frame = data_frame.mask(data_frame.isna(), pd.NA)
        logger.info("Converted numpy NaN values to pd.NA.")

        # Step 5: Convert column types to appropriate nullable pandas types
        for column_name in data_frame.columns:
            column_data = data_frame[column_name]
            
            if column_data.dtype.kind == 'f':  # Float columns
                try:
                    # Try converting to nullable Int64 if values are whole numbers
                    data_frame[column_name] = pd.to_numeric(column_data, errors='coerce').astype('Int64')
                except Exception:
                    # Fallback to nullable Float64
                    data_frame[column_name] = column_data.astype('Float64')

            elif column_data.dtype == object:
                # Convert object columns to pandas' nullable string dtype
                data_frame[column_name] = column_data.astype('string')

            # Leave other dtypes as-is (e.g., boolean, datetime)

        logger.info("Converted DataFrame columns to nullable pandas dtypes.")

        # Step 6: Force all columns to nullable string (optional)
        data_frame = data_frame.astype("string")
        logger.info("Converted all DataFrame columns to string type.")

        # Step 7: Log result preview
        logger.info("Final DataFrame column types:\n%s", data_frame.dtypes)
        logger.info("DataFrame preview (first 20 rows):\n%s", data_frame.head(20))

        return data_frame

    except Exception as error:
        logger.error(f"Error reading CSV from S3: {error}", exc_info=True)
        raise






def map_csv_row_to_flat_json(csv_row_dict, mapping_configuration):
    """
    Maps a CSV row dictionary into a flat JSON structure using a mapping configuration.

    :param csv_row_dict: Dictionary representing a single row from a CSV file
    :param mapping_configuration: Dictionary mapping JSON keys to CSV column names or default/static values
    :return: Dictionary representing a flat JSON object constructed from the row
    """
    try:
        logger.info("Starting mapping of CSV row to flat JSON object.")

        # Initialize result JSON object
        mapped_json = {}

        # Extract column names from the CSV row
        csv_column_names = set(csv_row_dict.keys())

        for target_json_key, mapping_value in mapping_configuration.items():
            if mapping_value in csv_column_names:
                # Value is dynamic: map from CSV column
                cell_value = csv_row_dict.get(mapping_value)

                if pd.notna(cell_value):
                    mapped_json[target_json_key] = cell_value
                else:
                    mapped_json[target_json_key] = ""
                    logger.debug(f"Missing or null value for CSV column '{mapping_value}', setting empty string.")
            else:
                # Value is static or default: use as-is or fallback to empty string
                mapped_json[target_json_key] = mapping_value if mapping_value else ""
                if not mapping_value:
                    logger.debug(f"No mapping or static value for JSON key '{target_json_key}', setting empty string.")

        logger.info("Completed mapping for row.")
        return mapped_json

    except Exception as error:
        logger.error(f"Error while mapping CSV row to JSON: {error}", exc_info=True)
        raise






def flatten_to_nested(flat_json_dict, separator='|'):
    """
    Converts a flat JSON dictionary with compound keys into a nested dictionary or list structure.
    Keys separated by a specified separator are interpreted as nested paths.
    Numeric keys are treated as list indices.

    Example:
        Input: {
            "user|name": "Alice",
            "user|roles|0": "admin",
            "user|roles|1": "editor"
        }
        Output: {
            "user": {
                "name": "Alice",
                "roles": ["admin", "editor"]
            }
        }

    :param flat_json_dict: A flat dictionary with compound keys
    :param separator: Separator used in the flat keys (default is '|')
    :return: Nested dictionary or list
    """
    try:
        logger.info("Starting to convert flat JSON to nested structure.")
        
        nested_result = {}

        # First pass: Build nested structure (dicts and lists) from flat keys
        for compound_key, value in flat_json_dict.items():
            key_parts = compound_key.split(separator)
            current_level = nested_result

            for index, key_part in enumerate(key_parts):
                # Convert numeric keys to integers for list indexing
                try:
                    key_part = int(key_part)
                except ValueError:
                    pass

                is_last_part = index == len(key_parts) - 1

                if is_last_part:
                    # Final key: assign value
                    if isinstance(key_part, int):
                        while len(current_level) <= key_part:
                            current_level.append(None)
                        current_level[key_part] = value
                    else:
                        current_level[key_part] = value
                else:
                    next_key_part = key_parts[index + 1]
                    try:
                        int(next_key_part)
                        next_is_list = True
                    except ValueError:
                        next_is_list = False

                    # Prepare next level
                    if isinstance(key_part, int):
                        while len(current_level) <= key_part:
                            current_level.append(None)
                        if current_level[key_part] is None:
                            current_level[key_part] = [] if next_is_list else {}
                        current_level = current_level[key_part]
                    else:
                        if key_part not in current_level:
                            current_level[key_part] = [] if next_is_list else {}
                        current_level = current_level[key_part]

        logger.info("Nested structure created from flat JSON.")

        # Second pass: Convert dicts with all numeric string keys into proper lists
        processing_stack = [(None, nested_result)]
        while processing_stack:
            parent, current = processing_stack.pop()

            if isinstance(current, dict):
                all_keys_are_numeric = all(isinstance(k, str) and k.isdigit() for k in current.keys())

                for k, v in current.items():
                    processing_stack.append((current, v))

                if all_keys_are_numeric:
                    # Convert this dict into list and assign to parent if known
                    sorted_items = sorted(((int(k), v) for k, v in current.items()), key=lambda x: x[0])
                    converted_list = [v for _, v in sorted_items]

                    if parent is not None:
                        for k, v in parent.items():
                            if v == current:
                                parent[k] = converted_list
                                break
                    else:
                        nested_result = converted_list

            elif isinstance(current, list):
                for item in current:
                    processing_stack.append((current, item))

        logger.info("Completed flatten_to_nested conversion.")
        return nested_result

    except Exception as error:
        logger.error(f"Error in flatten_to_nested: {error}", exc_info=True)
        raise







def transform_special_fields(flat_payload_dict, field_transformation_rules):
    """
    Applies special field transformations to a flat JSON payload based on provided rules.
    
    Supported transformation types:
      - "date": Formats a date string to a specified format
      - "datetime": Formats a datetime string to a specified format
      - "prefix": Prepends a prefix to the value if it doesn't already start with it

    :param flat_payload_dict: Flat JSON dictionary where transformations will be applied
    :param field_transformation_rules: Dictionary of transformation rules per field
    :return: Modified flat JSON dictionary
    """
    try:
        logger.info("Starting transformation of special fields in flat payload.")

        for field_name, transformation_rule in field_transformation_rules.items():
            if field_name not in flat_payload_dict:
                logger.debug(f"Field '{field_name}' not found in payload. Skipping.")
                continue

            field_value = flat_payload_dict[field_name]

            if pd.isna(field_value) or field_value in [None, ""]:
                logger.debug(f"Field '{field_name}' has empty or null value. Skipping.")
                continue

            transformation_type = transformation_rule.get("type")

            # DATE or DATETIME transformation
            if transformation_type in ["date", "datetime"]:
                date_format = transformation_rule.get("format")
                if not date_format:
                    date_format = "%Y-%m-%d" if transformation_type == "date" else "%Y-%m-%d %H:%M:%S"

                parsed_date = pd.to_datetime(str(field_value), errors='coerce')

                if pd.isnull(parsed_date):
                    logger.debug(f"Unable to parse '{field_value}' as {transformation_type}. Leaving unchanged.")
                    continue

                formatted_value = parsed_date.strftime(date_format)
                flat_payload_dict[field_name] = formatted_value
                logger.debug(f"Transformed field '{field_name}' to '{formatted_value}' using format '{date_format}'.")

            # PREFIX transformation
            elif transformation_type == "prefix":
                prefix_value = transformation_rule.get("prefix", "")
                value_as_string = str(field_value)

                if not value_as_string.startswith(prefix_value):
                    flat_payload_dict[field_name] = f"{prefix_value}{value_as_string}"
                    logger.debug(f"Added prefix '{prefix_value}' to field '{field_name}'.")

        logger.info("Completed special field transformations.")
        return flat_payload_dict

    except Exception as error:
        logger.error(f"Error during special field transformation: {error}", exc_info=True)
        raise






def apply_conditional_field_rules_generic(flat_payload_dict, csv_row_dict, conditional_rules_config):
    """
    Applies a set of conditional rules to a flat payload based on values from a CSV row.

    Rule types supported:
        - field_group
        - conditional_add
        - conditional_add_default
        - conditional_remove

    Also ensures "CategoryCode" is included if any "assignmentsEFF" fields are added.

    :param flat_payload_dict: dict representing flattened JSON payload
    :param csv_row_dict: dict representing the CSV row data
    :param conditional_rules_config: dict containing conditional rule configurations
    :return: updated flat_payload_dict
    """
    try:
        logger.info("Applying conditional rules to flat payload.")

        desired_additions = {}          # Fields to be added
        managed_keys = set()            # Keys controlled by any rule
        all_group_prefixes = []         # All prefixes declared in field_group rules
        keep_group_prefixes = set()     # Valid prefixes to retain

        # Helper replacements for previously nested function logic

        # Flattened loop begins
        for rule_name, rule_config in (conditional_rules_config or {}).items():
            rule_type = rule_config.get("type")

            # Handle field_group rules
            if rule_type == "field_group":
                field_prefixes = rule_config.get("field_prefixes", []) or []
                all_group_prefixes.extend(field_prefixes)

                condition_mappings = rule_config.get("conditions", {}) or {}
                for csv_field, prefix_value in condition_mappings.items():
                    row_value = csv_row_dict.get(csv_field)
                    if pd.notna(row_value) and str(row_value).strip().lower() not in ["", "nan", "none"]:
                        keep_group_prefixes.add(prefix_value)
                continue

            # Handle conditional_add and conditional_add_default
            if rule_type in ("conditional_add", "conditional_add_default"):
                conditions_dict = rule_config.get("conditions", {}) or {}
                fields_to_add = rule_config.get("fields", {}) or {}

                for key in fields_to_add.keys():
                    managed_keys.add(key)

                condition_pass = True
                for condition_field, expected_value in conditions_dict.items():
                    actual_value = csv_row_dict.get(condition_field, "")
                    actual_value = "" if pd.isna(actual_value) else str(actual_value).strip()
                    expected_value = str(expected_value).strip()

                    if expected_value == "__nonempty__":
                        if actual_value.lower() in ["", "nan", "none"]:
                            condition_pass = False
                            break
                    elif actual_value != expected_value:
                        condition_pass = False
                        break

                if condition_pass:
                    for flat_key, source in fields_to_add.items():
                        if isinstance(source, str) and source.startswith("__from_csv__:"):
                            csv_field = source.replace("__from_csv__:", "")
                            field_val = csv_row_dict.get(csv_field)
                            if pd.notna(field_val) and str(field_val).strip().lower() not in ["", "nan", "none"]:
                                desired_additions[flat_key] = str(field_val).strip()
                        else:
                            desired_additions[flat_key] = source
                continue

            # Handle conditional_remove
            if rule_type == "conditional_remove":
                conditions_dict = rule_config.get("conditions", {}) or {}
                condition_pass = True

                for condition_field, expected_value in conditions_dict.items():
                    actual_value = csv_row_dict.get(condition_field, "")
                    actual_value = "" if pd.isna(actual_value) else str(actual_value).strip()
                    expected_value = str(expected_value).strip()

                    if expected_value == "__nonempty__":
                        if actual_value.lower() in ["", "nan", "none"]:
                            condition_pass = False
                            break
                    elif actual_value != expected_value:
                        condition_pass = False
                        break

                if condition_pass:
                    for key_to_remove in rule_config.get("fields", []) or []:
                        managed_keys.add(key_to_remove)
                        desired_additions.pop(key_to_remove, None)
                continue

            # Generic: track managed keys
            for key in rule_config.get("fields", {}) or {}:
                managed_keys.add(key)

        # Pass 2: Remove unwanted keys
        prefixes_to_remove = [prefix for prefix in all_group_prefixes if prefix not in keep_group_prefixes]

        for existing_key in list(flat_payload_dict.keys()):
            if existing_key in managed_keys and existing_key not in desired_additions:
                flat_payload_dict.pop(existing_key, None)
                continue
            if any(existing_key.startswith(prefix) for prefix in prefixes_to_remove):
                flat_payload_dict.pop(existing_key, None)
                continue

        # Pass 3: Add new keys
        for key, value in desired_additions.items():
            if any(key.startswith(prefix) for prefix in prefixes_to_remove):
                continue
            flat_payload_dict[key] = value

        # Final enforcement: ensure CategoryCode for assignmentsEFF
        eff_prefix = "workRelationships|0|assignments|0|assignmentsEFF|0|"
        category_key = eff_prefix + "CategoryCode"

        if any(k.startswith(eff_prefix) for k in flat_payload_dict.keys()) and category_key not in flat_payload_dict:
            flat_payload_dict[category_key] = "PER_ASG_EIT"
            logger.info(f"Auto-added missing required key '{category_key}'.")

        logger.info("Conditional field rules applied successfully.")
        return flat_payload_dict

    except Exception as error:
        logger.error(f"Failed to apply conditional field rules: {error}", exc_info=True)
        raise





def lookup_values(row_data_dict, lookup_rules_config, call_hcm_api_get_function, base_host_url, jwt_auth_token):
    """
    Resolves lookup values for a given CSV row using HCM API calls and rule-based metadata.

    For each rule:
        - Input field is checked for presence in the row
        - If found, a GET API call is made to fetch matching metadata
        - Result is cached to avoid repeated requests for the same input
        - Response value is extracted and stored in the final lookup_results

    Parameters:
        row_data_dict (dict): The row values from the CSV file
        lookup_rules_config (list[dict]): List of lookup rule dictionaries
        call_hcm_api_get_function (function): Function used to make GET API calls
        base_host_url (str): The HCM host URL for API calls
        jwt_auth_token (str): JWT token to authorize the API request

    Returns:
        dict: Dictionary of resolved lookup values {target_field: resolved_value}
    """
    resolved_lookup_values = {}
    api_call_cache = {}

    for rule in lookup_rules_config:
        input_field_key = rule.get("input_field")
        if not input_field_key:
            logger.debug("Skipping rule with missing input_field key.")
            continue

        input_value = row_data_dict.get(input_field_key)
        if not input_value:
            logger.debug(f"Skipping rule as input value not found in row for field: {input_field_key}")
            continue

        # Build query parameters with row values substituted
        raw_query_params = rule.get("query_params", {})
        formatted_query_params = {}

        for param_key, param_template in raw_query_params.items():
            try:
                formatted_query_params[param_key] = param_template.format(**row_data_dict)
            except KeyError as key_error:
                logger.warning(f"Missing key {key_error} in row data for query formatting. Rule skipped.")
                formatted_query_params[param_key] = ""

        resource_endpoint = rule.get("resource")
        if not resource_endpoint:
            logger.debug("Skipping rule with missing resource path.")
            continue

        # Build a cache key from the resource and the resolved query parameters
        cache_lookup_key = (resource_endpoint, frozenset(formatted_query_params.items()))
        if cache_lookup_key in api_call_cache:
            api_response = api_call_cache[cache_lookup_key]
            logger.debug(f"Cache hit for resource: {resource_endpoint} with params: {formatted_query_params}")
        else:
            logger.info(f"Calling HCM API for resource: {resource_endpoint} with params: {formatted_query_params}")
            api_response = call_hcm_api_get_function(
                resource_path=resource_endpoint,
                query_params=formatted_query_params,
                jwt_token=jwt_auth_token
            )
            api_call_cache[cache_lookup_key] = api_response

        if api_response.get("statusCode") != 200:
            logger.warning(f"Lookup API call failed for rule '{rule.get('name', 'Unnamed')}', status: {api_response.get('statusCode')}")
            continue

        try:
            response_body = api_response.get("body", {})
            if isinstance(response_body, str):
                response_body = json.loads(response_body)

            items_list = response_body.get("items", [])
            if not items_list:
                logger.info(f"No results found in lookup response for rule '{rule.get('name')}'")
                continue

            first_item = items_list[0]
            target_value = first_item.get(rule.get("response_field"))

            if target_value:
                resolved_lookup_values[rule["target_field"]] = target_value
                logger.info(f"Resolved value for '{rule['target_field']}' from rule '{rule.get('name')}'")
            else:
                logger.info(f"Response field missing or empty in first item for rule '{rule.get('name')}'")

        except Exception as error:
            logger.warning(f"Failed to parse lookup response for rule '{rule.get('name')}': {error}", exc_info=True)
            continue

    return resolved_lookup_values






def apply_lookup_values_to_payload(flat_payload_dict, resolved_lookup_values):
    """
    Update a flat JSON payload dictionary using resolved lookup values.

    For each entry in the resolved lookup dictionary:
        - Finds all keys in the payload that either:
            - Exactly match the target field name
            - End with '|<target_field>' (e.g., nested paths)
        - Replaces their value with the resolved lookup value.

    Parameters:
        flat_payload_dict (dict): The flat JSON payload to update
        resolved_lookup_values (dict): Dict containing {target_field: resolved_value} pairs

    Returns:
        dict: Updated flat_payload_dict with lookup values applied
    """
    if not resolved_lookup_values:
        logger.info("No lookup values to apply to payload.")
        return flat_payload_dict

    logger.info("Applying resolved lookup values to payload.")

    for target_field_name, resolved_value in resolved_lookup_values.items():
        match_count = 0

        for payload_key in flat_payload_dict.keys():
            if payload_key == target_field_name or payload_key.endswith(f"|{target_field_name}"):
                flat_payload_dict[payload_key] = resolved_value
                match_count += 1

        logger.info(
            f"Applied value for '{target_field_name}' to {match_count} matching key(s) in payload."
        )

    return flat_payload_dict


def log_failed_post(
    failure_records, s3_bucket, s3_key,
    worker_success_count, salary_success_count,
    total_worker_calls, total_salary_calls
):
    """
    Converts a list of failure dictionaries into a formatted DataFrame,
    logs the structure, and uploads the CSV to S3.

    Args:
        failure_records (list): List of failure dictionaries
        s3_bucket (str): S3 bucket name
        s3_key (str): S3 object key (path)
        worker_success_count (int): Number of successful Worker API posts
        salary_success_count (int): Number of successful Salary API posts
        total_worker_calls (int): Total Worker API POST attempts
        total_salary_calls (int): Total Salary API POST attempts

    Returns:
        pd.DataFrame: DataFrame of formatted failure logs
    """


    if not failure_records:
        logger.info("[log_failed_post] No failures to log.")
        return pd.DataFrame()

    logger.info(f"[log_failed_post] Preparing to log {len(failure_records)} failure records.")

    formatted_failures = []

    for i, failure in enumerate(failure_records):
        logger.debug(f"[log_failed_post] Formatting failure {i} with keys: {list(failure.keys())}")
        
        # Parse JSON payload safely
        payload_str = failure.get("payload_json", "{}")
        try:
            payload = json.loads(payload_str or "{}")
        except Exception as e:
            logger.warning(f"[log_failed_post] Failed to parse payload_json: {e}")
            payload = {}

        # Extract candidate info
        candidate_id = (
            failure.get("CandidateId")
            or payload.get("TaleoCandidateID")
            or (payload.get("externalIdentifiers", [{}])[0].get("ExternalIdentifierNumber", "UNKNOWN"))
            or "UNKNOWN"
        )

        candidate_name = failure.get("CandidateName")
        if not candidate_name:
            name_parts = [
                payload.get("FirstName") or payload.get("names", [{}])[0].get("FirstName", ""),
                payload.get("MiddleNames") or payload.get("names", [{}])[0].get("MiddleNames", ""),
                payload.get("LastName") or payload.get("names", [{}])[0].get("LastName", "")
            ]
            candidate_name = " ".join(part for part in name_parts if part).strip() or "UNKNOWN"

        # Other fields
        person_number = failure.get("person_number", "") or failure.get("personNumber", "") or "N/A"
        person_id = failure.get("person_id", "") or failure.get("personId", "") or "N/A"

        workers_status = failure.get("workers_status", "N/A")
        workers_error = failure.get("workers_error_message") or failure.get("workers_error") or "N/A"

        salaries_status = failure.get("salaries_status", "N/A")
        salaries_error = failure.get("salaries_error_message") or failure.get("salaries_error") or "N/A"

        formatted_failures.append({
            "Row Index": failure.get("row_index", "N/A"),
            "Log ID": str(uuid.uuid4()),
            "Candidate ID": candidate_id or "UNKNOWN",
            "Candidate Name": candidate_name or "UNKNOWN",
            "Person Number": person_number,
            "Person ID": person_id,
            "Workers API Status": workers_status,
            "Workers API Error": workers_error,
            "Salaries API Status": salaries_status,
            "Salaries API Error": salaries_error
        })

    df = pd.DataFrame(formatted_failures)
    logger.info(f"[log_failed_post] Created failure DataFrame with {len(df)} rows.")

    # Append summary rows
    summary_rows = pd.DataFrame([
        {
            "Row Index": "",
            "Log ID": "",
            "Candidate ID": "",
            "Candidate Name": "",
            "Person Number": "",
            "Person ID": "",
            "Workers API Status": "",
            "Workers API Error": "",
            "Salaries API Status": "",
            "Salaries API Error": ""
        },
        {
            "Row Index": "TOTAL Worker API Calls",
            "Log ID": f"Success: {worker_success_count}",
            "Candidate ID": f"Failed: {total_worker_calls - worker_success_count}",
            "Candidate Name": "",
            "Person Number": "",
            "Person ID": "",
            "Workers API Status": "",
            "Workers API Error": "",
            "Salaries API Status": "",
            "Salaries API Error": ""
        },
        {
            "Row Index": "TOTAL Salaries API Calls",
            "Log ID": f"Success: {salary_success_count}",
            "Candidate ID": f"Failed: {total_salary_calls - salary_success_count}",
            "Candidate Name": "",
            "Person Number": "",
            "Person ID": "",
            "Workers API Status": "",
            "Workers API Error": "",
            "Salaries API Status": "",
            "Salaries API Error": ""
        }
    ])

    df_final = pd.concat([df, summary_rows], ignore_index=True)

    # Log preview of DataFrame
    logger.info(f"[log_failed_post] Final failure DataFrame preview:\n{df_final.head(20).to_string(index=False)}")

    # Save to S3
    try:
        csv_buffer = StringIO()
        df_final.to_csv(csv_buffer, index=False)
        boto3.client("s3").put_object(Bucket=s3_bucket, Key=s3_key, Body=csv_buffer.getvalue())
        logger.info(f"[log_failed_post] Uploaded failure log to s3://{s3_bucket}/{s3_key}")
    except Exception as e:
        logger.error(f"[log_failed_post] Failed to upload CSV to S3: {e}")

    return df_final


def pre_validation_logic(row, pre_validation_rules, jwt_token, row_index, workers_failures):
    """
    Runs pre-validation on a single row of candidate data based on ordered rules.

    Rules executed in order:
      1) Check by WPEmployeeID
      2) Check by SSN
      3) Check by Email/Phone
      4) Check by Name + DOB

    If an ACTIVE assignment is found, row is skipped. Otherwise, returns action code.
    """
    row_dict = row.to_dict()
    logger.info(f"[pre_validation] Row {row_index} start: TaleoCandidateID={row_dict.get('TaleoCandidateID')}")

    found_non_active_match = False

    ordered_rules = [
        "Check by WPEmployeeID",
        "Check by SSN",
        "Check by Email/Phone",
        "Check by Name+DOB"
    ]
    name_to_rule = {r.get('name'): r for r in pre_validation_rules}
    rules_to_run = [name_to_rule[n] for n in ordered_rules if n in name_to_rule]

    for rule in rules_to_run:
        rule_name = rule.get("name")

        # --- Skip if required field is missing ---
        if rule_name == "Check by WPEmployeeID" and not row_dict.get("WPEmployeeID"):
            logger.info(f"[pre_validation] Row {row_index} skipping {rule_name} (no WPEmployeeID)")
            continue
        if rule_name == "Check by SSN" and not row_dict.get("SSN"):
            logger.info(f"[pre_validation] Row {row_index} skipping {rule_name} (no SSN)")
            continue
        if rule_name == "Check by Email/Phone" and not (
            row_dict.get("Email") or row_dict.get("MobilePhone") or row_dict.get("HomePhone")
        ):
            logger.info(f"[pre_validation] Row {row_index} skipping {rule_name} (no Email/Phone)")
            continue
        if rule_name == "Check by Name+DOB" and not (
            row_dict.get("FirstName") and row_dict.get("LastName") and row_dict.get("DateOfBirth")
        ):
            logger.info(f"[pre_validation] Row {row_index} skipping {rule_name} (missing Name or DOB)")
            continue

        # --- Build the query string ---
        try:
            query = rule["query_template"].format(
                WPEmployeeID=str(row_dict.get("WPEmployeeID", "")).strip(),
                SSN=str(row_dict.get("SSN", "")).strip(),
                Email=str(row_dict.get("Email", "")).strip(),
                Phone=str(row_dict.get("MobilePhone", "") or row_dict.get("HomePhone", "") or "").strip(),
                FirstName=str(row_dict.get("FirstName", "")).strip(),
                FirstInitial=(str(row_dict.get("FirstName", "")).strip()[:1] if row_dict.get("FirstName") else ""),
                LastName=str(row_dict.get("LastName", "")).strip(),
                DateOfBirth=str(row_dict.get("DateOfBirth", "")).strip()
            )
        except Exception as e:
            logger.error(f"[pre_validation] Row {row_index} failed to build query for {rule_name}: {e}")
            continue

        params = {"q": query}
        if rule.get("expand"):
            params["expand"] = rule["expand"]

        logger.info(f"[pre_validation] Row {row_index} executing {rule_name} with query: {query}")

        try:
            response = call_hcm_api_get(workers_endpoint, params, jwt_token)
        except Exception as e:
            logger.error(f"[pre_validation] Row {row_index} API error for {rule_name}: {e}")
            continue

        if response.get("statusCode") != 200:
            logger.warning(f"[pre_validation] Row {row_index} API returned status {response.get('statusCode')}")
            continue

        try:
            data = json.loads(response.get("body", "{}"))
        except Exception as e:
            logger.error(f"[pre_validation] Row {row_index} failed to parse API body: {e}")
            continue

        items = data.get("items", [])
        if not items:
            logger.info(f"[pre_validation] Row {row_index} - No matches found for {rule_name}")
            continue

        for item in items:
            person_id = item.get("PersonId", "")
            person_number = item.get("PersonNumber", "")

            for wr in item.get("workRelationships", []):
                for assignment in wr.get("assignments", []):
                    status = assignment.get("AssignmentStatusType", "")
                    if status == rule.get("active_status"):
                        # Found an ACTIVE record – log and skip this candidate
                        skip_message = rule.get("skip_error_message", "Employee already exists (ACTIVE)")
                        logger.info(f"[pre_validation] Row {row_index} skipped: ACTIVE assignment found.")
                        workers_failures.append({
                            "row_index": row_index,
                            "CandidateId": row_dict.get("TaleoCandidateID", "No Candidate ID"),
                            "CandidateName": f"{row_dict.get('FirstName', '')} {row_dict.get('LastName', '')}".strip() or "No Candidate Name",
                            "workers_status": "SKIPPED",
                            "workers_error_message": skip_message,
                            "salaries_status": "NOT_ATTEMPTED",
                            "salaries_error_message": "Skipped due to pre-validation failure",
                            "payload_json": json.dumps(row_dict),
                            "person_id": person_id or "Not Retrieved",
                            "person_number": person_number or "Not Retrieved"
                        })
                        return None
                    else:
                        found_non_active_match = True

        if found_non_active_match:
            break

    # --- Final Action Code Decision ---
    action_code = "ADD_PWK_EMP" if found_non_active_match else "ADD_PEN_WKR"
    logger.info(f"[pre_validation] Row {row_index} ActionCode set to {action_code}")
    return action_code




## Main processing block
df = read_csv_from_s3(S3_BUCKET, S3_KEY)
logger.info(f"Loaded input CSV from s3://{S3_BUCKET}/{S3_KEY}; rows={len(df)}")
logger.info(f"Columns: {list(df.columns)}")

workers_failures = []
salaries_failures = []
worker_success_count = 0
salary_success_count = 0
jwt_token = None  # You should assign a valid JWT token here

for index, row in df.iterrows():
    row_dict = row.to_dict()
    candidate_id = row_dict.get("TaleoCandidateID", "No Candidate ID")
    candidate_name = " ".join(filter(None, [row_dict.get("FirstName", ""), row_dict.get("LastName", "")])) or "No Candidate Name"

    logger.info(f"\n=== Processing Row {index}: CandidateID={candidate_id}, WPEmployeeID={row_dict.get('WPEmployeeID')} ===")

    # 1. Pre-validation
    try:
        action_code = pre_validation_logic(row, pre_validation_rules, jwt_token, index, workers_failures)
    except Exception as e:
        logger.error(f"[Main] Pre-validation failed for row {index}: {e}", exc_info=True)
        workers_failures.append({
            "row_index": index,
            "CandidateId": candidate_id,
            "CandidateName": candidate_name,
            "workers_status": "PREVALIDATION_ERROR",
            "workers_error_message": str(e),
            "salaries_status": "NOT_ATTEMPTED",
            "salaries_error_message": "Skipped due to pre-validation failure",
            "payload_json": json.dumps(row_dict),
            "person_id": "Not Retrieved",
            "person_number": "Not Retrieved"
        })
        continue

    if not action_code:
        logger.info(f"[Main] Row {index} skipped by pre-validation.")
        continue

    # 2. Lookup values
    try:
        lookup_results = lookup_values(
            row_data_dict=row_dict,
            lookup_rules_config=metadata.get("lookup_rules", []),
            call_hcm_api_get_function=call_hcm_api_get,
            base_host_url=metadata.get("host_url"),
            jwt_auth_token=jwt_token
        )
    except Exception as e:
        logger.error(f"[Main] Lookup failed for row {index}: {e}", exc_info=True)
        lookup_results = {}

    # 3. Build Workers Payload
    worker_payload_flat = map_csv_row_to_flat_json(row_dict, workers_payload_json)
    worker_payload_flat["workRelationships|0|assignments|0|ActionCode"] = action_code
    worker_payload_flat = apply_lookup_values_to_payload(worker_payload_flat, lookup_results)
    worker_payload_flat = transform_special_fields(worker_payload_flat, field_transformations)
    worker_payload_flat = apply_conditional_field_rules_generic(
        flat_payload_dict =worker_payload_flat,
        csv_row_dict=row_dict,
        conditional_rules_config=metadata.get("conditional_field_rules", {})
    )
    worker_payload_nested = flatten_to_nested(worker_payload_flat)

    logger.info(f"[Main] Workers Payload for row {index}:\n{json.dumps(worker_payload_nested, indent=2)}")

    # 4. POST Worker
    try:
        worker_response = call_hcm_api_post(
            workers_endpoint, workers_query_param, worker_payload_nested, jwt_token, host_url
        )
    except Exception as e:
        logger.exception(f"[Main] Workers POST exception for row {index}: {e}")
        workers_failures.append({
            "row_index": index,
            "CandidateId": candidate_id,
            "CandidateName": candidate_name,
            "workers_status": "POST_EXCEPTION",
            "workers_error_message": str(e),
            "salaries_status": "NOT_ATTEMPTED",
            "salaries_error_message": "Not attempted due to worker POST failure",
            "payload_json": json.dumps(worker_payload_nested),
            "person_id": "Not Retrieved",
            "person_number": "Not Retrieved"
        })
        continue

    worker_status_code = worker_response.get("statusCode", "No Status Code")
    worker_response_body = worker_response.get("body", "No Response Body")

    logger.info(f"[Main] Workers API response for row {index}: status={worker_status_code}")

    if worker_status_code == 201:
        worker_success_count += 1
        try:
            parsed_worker = json.loads(worker_response_body)
            person_id = parsed_worker.get("PersonId", "Not Returned")
            person_number = parsed_worker.get("PersonNumber", "Not Returned")
        except Exception as e:
            logger.warning(f"[Main] Could not parse worker response body: {e}")
            person_id = "Not Parsed"
            person_number = "Not Parsed"
    else:
        workers_failures.append({
            "row_index": index,
            "CandidateId": candidate_id,
            "CandidateName": candidate_name,
            "workers_status": str(worker_status_code),
            "workers_error_message": worker_response_body or "No Error Details",
            "salaries_status": "NOT_ATTEMPTED",
            "salaries_error_message": "Not attempted due to worker POST failure",
            "payload_json": json.dumps(worker_payload_nested),
            "person_id": "Not Returned",
            "person_number": "Not Returned"
        })
        continue

    # 5. Build Salaries Payload
    salary_payload_flat = map_csv_row_to_flat_json(row_dict, salaries_payload_json)
    salary_payload_flat["Salaries|0|AssignmentId"] = person_id
    salary_payload_flat = apply_lookup_values_to_payload(salary_payload_flat, lookup_results)
    salary_payload_flat = transform_special_fields(salary_payload_flat, field_transformations)
    salary_payload_nested = flatten_to_nested(salary_payload_flat)
    for key, value in salary_payload_nested.items():
        if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
            salary_payload_nested[key] = value[0]
    salary_payload_nested = salary_payload_nested["Salaries"]
    
    logger.info(f"[Main] Salaries Payload for row {index}:\n{json.dumps(salary_payload_nested, indent=2)}")

    # 6. POST Salary
    try:
        salary_response = call_hcm_api_post(
            salaries_endpoint, salaries_query_param, salary_payload_nested, jwt_token, host_url
        )
    except Exception as e:
        logger.exception(f"[Main] Salaries POST exception for row {index}: {e}")
        salaries_failures.append({
            "row_index": index,
            "CandidateId": candidate_id,
            "CandidateName": candidate_name,
            "workers_status": worker_status_code,
            "workers_error_message": "Successful",
            "salaries_status": "POST_EXCEPTION",
            "salaries_error_message": str(e),
            "payload_json": json.dumps(salary_payload_nested),
            "person_id": person_id,
            "person_number": person_number
        })
        continue

    salary_status_code = salary_response.get("statusCode", "No Status Code")
    salary_body = salary_response.get("body", "No Response Body")
    logger.info(f"[Main] Salaries API response for row {index}: status={salary_status_code}")

    if salary_status_code == 201:
        salary_success_count += 1
    else:
        salaries_failures.append({
            "row_index": index,
            "CandidateId": candidate_id,
            "CandidateName": candidate_name,
            "workers_status": worker_status_code,
            "workers_error_message": "Successful",
            "salaries_status": str(salary_status_code),
            "salaries_error_message": salary_body or "No Error Details",
            "payload_json": json.dumps(salary_payload_nested),
            "person_id": person_id,
            "person_number": person_number
        })

# --- Final Reporting ---
total_worker_calls = worker_success_count + len(workers_failures)
total_salary_calls = salary_success_count + len(salaries_failures)

logger.info("======== Summary Report ========")
logger.info(f"Worker API Calls:   Total: {total_worker_calls}, Success: {worker_success_count}, Failed: {len(workers_failures)}")
logger.info(f"Salary API Calls:   Total: {total_salary_calls}, Success: {salary_success_count}, Failed: {len(salaries_failures)}")

# Combine failures
combined_failures = workers_failures + salaries_failures
for rec in combined_failures:
    rec["CandidateId"] = rec.get("CandidateId", "No Candidate ID")
    rec["CandidateName"] = rec.get("CandidateName", "No Candidate Name")
    rec["workers_status"] = rec.get("workers_status", "No Status Code")
    rec["workers_error_message"] = rec.get("workers_error_message", "No Error Details")
    rec["salaries_status"] = rec.get("salaries_status", "No Status Code")
    rec["salaries_error_message"] = rec.get("salaries_error_message", "No Error Details")

# Final failure report
FAILED_LOG_KEY = 'INT024/failed_post_log.csv'
final_failures_df = log_failed_post(
    failure_records = combined_failures,
    s3_bucket=S3_BUCKET,
    s3_key=FAILED_LOG_KEY,
    worker_success_count=worker_success_count,
    salary_success_count=salary_success_count,
    total_worker_calls=total_worker_calls,
    total_salary_calls=total_salary_calls
    #df_success_count=worker_success_count + salary_success_count,
    #total_calls=total_worker_calls + total_salary_calls,
    #api_type="Workers/Salaries"
)

logger.info("[Main] Final failure report saved and completed.")