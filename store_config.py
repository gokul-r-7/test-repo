def store_config_in_dynamodb(**context):
    """
    Store final DAG run status and metadata in DynamoDB in flat key:value format,
    including flattened input_config_details.
    """
    print("--- Finalizing and storing DAG metadata in DynamoDB ---")
    table = ensure_dynamodb_table_exists()
    ti = context["ti"]

    dag_run_id = context["dag_run"].run_id
    run_uuid = str(uuid.uuid4())
    created_date = datetime.now().isoformat()

    # Fetch input config
    config = ti.xcom_pull(task_ids="parse_and_validate_config", key="validated_config")
    source = config["sources"][0]
    source_name = source["name"]
    env = config.get("env", "dev")

    # Extract triggered_by fields if available
    triggered_by_name = config.get("triggered_by", "unknown")
    triggered_by_email = config.get("email", "unknown")

    # Extract input config details (flattened)
    warehouse_key = source.get("warehouse", "")
    connection_key = source.get("connection", "")
    retention_policy_key = source.get("retention_policy", "")
    legal_hold_flag = source.get("legal_hold", False)

    # Also extract schema and table names from include -> schemas -> tables
    schema_names = []
    table_names = []
    include = source.get("include", {})
    schemas = include.get("schemas", [])
    for sch in schemas:
        sch_name = sch.get("name", "")
        if sch_name:
            schema_names.append(sch_name)
        tables = sch.get("tables", [])
        for t in tables:
            # Only when t has "name"
            table_name = t.get("name")
            if table_name:
                table_names.append(table_name)

    # Fetch job metadata
    job_metadata = ti.xcom_pull(task_ids="aggregate_job_metadata", key="job_metadata") or {}
    archive_jobs = job_metadata.get("archive_jobs", [])
    validate_jobs = job_metadata.get("validate_jobs", [])

    # Fetch report Lambda output
    lambda_raw = ti.xcom_pull(task_ids="report_generation_lambda", key="return_value")
    try:
        lambda_output = json.loads(lambda_raw) if lambda_raw else {}
        validation_report = lambda_output.get("validation_report", "")
        validation_summary = lambda_output.get("validation_summary_report", "")
    except Exception as e:
        print(f"Failed to parse Lambda output: {e}")
        validation_report = ""
        validation_summary = ""

    # Determine DAG status
    archive_status = all(job.get("status") == "SUCCEEDED" for job in archive_jobs)
    validate_status = all(job.get("status") == "SUCCEEDED" for job in validate_jobs)
    dag_status = "succeeded" if archive_status and validate_status else "failed"

    # Build item, flattened
    item = {
        "id": run_uuid,
        "source_name": source_name,
        "env": env,
        "airflow_run_id": dag_run_id,
        "created_date": created_date,
        "dag_status": dag_status,
        "triggered_by_name": triggered_by_name,
        "triggered_by_email": triggered_by_email,
        "validation_report_path": validation_report,
        "validation_summary_path": validation_summary,
        # input config details
        "input_warehouse": warehouse_key,
        "input_connection": connection_key,
        "input_retention_policy": retention_policy_key,
        "input_legal_hold": str(legal_hold_flag).lower(),
        "input_schema_names": ",".join(schema_names),
        "input_table_names": ",".join(table_names)
    }

    # Add flat archive job details
    for idx, job in enumerate(archive_jobs):
        prefix = f"archive_job_{idx}"
        item[f"{prefix}_job_run_id"] = job.get("job_run_id", "")
        item[f"{prefix}_status"] = job.get("status", "")
        item[f"{prefix}_start_time"] = job.get("start_time", "")
        item[f"{prefix}_end_time"] = job.get("end_time", "")
        item[f"{prefix}_duration"] = job.get("duration_seconds", "")
        # From script_args
        args = job.get("script_args", {})
        item[f"{prefix}_source_schema"] = args.get("--source_schema", "")
        item[f"{prefix}_source_table"] = args.get("--source_table", "")
        item[f"{prefix}_target_glue_table"] = args.get("--target_glue_table", "")

    # Add flat validate job details
    for idx, job in enumerate(validate_jobs):
        prefix = f"validate_job_{idx}"
        item[f"{prefix}_job_run_id"] = job.get("job_run_id", "")
        item[f"{prefix}_status"] = job.get("status", "")
        item[f"{prefix}_start_time"] = job.get("start_time", "")
        item[f"{prefix}_end_time"] = job.get("end_time", "")
        item[f"{prefix}_duration"] = job.get("duration_seconds", "")
        args = job.get("script_args", {})
        item[f"{prefix}_source_schema"] = args.get("--source_schema", "")
        item[f"{prefix}_source_table"] = args.get("--source_table", "")
        item[f"{prefix}_target_glue_table"] = args.get("--target_glue_table", "")

    # Store in DynamoDB
    try:
        table.put_item(Item=item)
        print("Successfully stored flattened metadata + input config in DynamoDB.")
    except Exception as e:
        raise AirflowException(f"Failed to store flattened metadata: {str(e)}")
