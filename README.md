Here’s a professionally written version of the **Minutes of Meeting (MoM)** based on the points you shared, with improved grammar and technical terminology:

---

**Minutes of Meeting**

**Date:** \[Insert Date]
**Attendees:** \[Insert Names]
**Subject:** Enhancements to Validation Report Accessibility, Audit Logs, and Data Access Control

---

### **Agenda Items & Discussion Summary**

---

#### **1. Validation Report Access via Amazon QuickSight**

**Current Implementation:**

* In the current setup, the validation report dashboard in Amazon QuickSight displays report URLs for all DAG runs.
* These URLs are publicly accessible to all users with access to QuickSight.

**Proposed Changes:**

* The dashboard should display report URLs **at the application level**, rather than for every DAG run.
* Reports should be **organized into separate folders** based on the application name.
* **S3 bucket policies** need to be configured so that only authorized users can access reports based on their application roles.
* Access to **event archived data** should also be restricted to users who have the corresponding application-level role permissions.

---

#### **2. Audit Logs**

**Current Implementation:**

* In the final step of the Airflow DAG, details such as Glue job metadata, input configuration, and S3 report paths are stored.
* Currently, user and email information is passed manually as part of the input JSON while triggering the DAG.

**Proposed Enhancements:**

* **Migrate audit log storage from DynamoDB to a relational database (e.g., PostgreSQL)** to allow for structured querying and reporting.
* **Define proper column names** for audit log records to improve readability and data integrity.
* **User identification should be automated**, retrieved dynamically from the triggering context rather than being passed manually via input configuration.

---

#### **3. Action Items Requiring Discussion with Raju**

* Define a strategy for **role-based access control** (RBAC) in QuickSight to ensure users can only view/download validation reports and archived data relevant to their assigned applications.
* Explore methods to **retrieve user identity dynamically** (e.g., via Airflow context or IAM role mapping) for capturing audit log information without manual input.
* Conduct a **feasibility study on archived data retrieval** mechanisms based on user roles and permissions.

---

### **Next Steps**

| Task                                                                   | Owner   | Deadline |
| ---------------------------------------------------------------------- | ------- | -------- |
| Define folder structure & S3 bucket policy requirements                | \[Name] | \[Date]  |
| Evaluate PostgreSQL schema for audit logs                              | \[Name] | \[Date]  |
| Schedule discussion with Raju on RBAC and user identification strategy | \[Name] | \[Date]  |
| Perform feasibility study on role-based data retrieval                 | \[Name] | \[Date]  |

---

Let me know if you'd like this in a downloadable format (PDF/Word), or need help preparing a presentation or follow-up email.

















Here's a structured and concise **Minutes of Meeting (MoM)** for the discussion that took place on **Tuesday**, summarizing both technical and strategic points from the discussions, particularly with Raju:

---

## **Minutes of Meeting – Tuesday**

### **1. Role-Based Access Control (RBAC) for Archived Data & Validation Reports**

#### **Discussion Summary:**

* **Objective:** Restrict access to validation reports and archived data in **Amazon QuickSight** based on user roles and application ownership.
* **Solution Proposed:**

  * Implement **RBAC using AWS Lake Formation** at the **Glue Data Catalog** and **S3** levels.
  * This would provide fine-grained access control to specific datasets and folders based on user/application roles.

#### **Key Points:**

* Validation and archived reports to be segregated by application.
* Access control managed via **Lake Formation permissions**, not only QuickSight.
* This will ensure only authorized users can access specific reports and historical data.

#### **Action Owner:**

* **Gokul** – To explore feasibility and lead implementation of Lake Formation-based access control.

---

### **2. Airflow DAG Design Enhancements**

#### **Current Implementation:**

* **Manual Trigger via Airflow UI** for both **Active** and **Retirement Archival** use cases.
* Input configurations are passed manually.

#### **Proposed Changes:**

##### **Active Archival:**

* **Input YAMLs to be stored in GitLab.**
* Changes to YAML will trigger **CI/CD pipeline**, which in turn triggers the **Airflow DAG**.
* Airflow DAG should consume the YAML content as its input config.
* Can be scheduled **daily**, but should only run when YAML input changes.

##### **Retirement Archival:**

* Will continue to be **manually triggered** via Airflow UI.
* No schedule needed – configurations passed manually as before.

#### **Action Owners:**

* **Dheena** – Set up CI/CD integration to trigger Airflow DAG from GitLab YAML changes.
* **Prasanth & Gokul** – Modify DAG code to support both archival types and handle input formats accordingly.

---

### **3. Capturing User Identity Dynamically in Audit Logs**

#### **Objective:**

* Eliminate manual input of user/email in audit logs.
* Automatically capture the **IAM or Airflow user identity** who triggered the DAG.

#### **Pending Discussion:**

* This point was **not yet discussed with Raju**.

#### **Action Owner:**

* **Gokul** – To explore dynamic user capture from **Airflow context**, possibly leveraging IAM role mappings or execution metadata.

---

### **Additional Notes:**

* The implementation of **AWS Lake Formation** is **not yet confirmed** for the project but identified as a strong candidate for access control.
* Audit logs are still under review for migration to **PostgreSQL** for structured querying and better schema design (discussed in the prior Friday meeting).

---

Let me know if you need this converted into a document or email format.

