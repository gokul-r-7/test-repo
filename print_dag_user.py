from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago
from airflow.utils.db import create_session
from airflow.models.log import Log

def print_trigger_user(**context):
    dag_run = context.get('dag_run')
    if not dag_run:
        print("No dag_run in context; can’t determine who triggered.")
        return

    dag_id = dag_run.dag_id
    exec_date = dag_run.execution_date

    print(f"Looking up trigger log for dag_id={dag_id}, execution_date={exec_date}")

    with create_session() as session:
        # Query Log table
        log_record = (
            session.query(Log)
            .filter(
                Log.dag_id == dag_id,
                Log.event == "trigger",
                Log.execution_date == exec_date
            )
            .order_by(Log.dttm.desc())
            .first()
        )

    if log_record:
        print("Found trigger log record:")
        print(f"  owner field: {log_record.owner}")
        print(f"  extra field: {log_record.extra}")
    else:
        print("No trigger log record found for this dag_run.")

default_args = {
    "owner": "airflow",
    "start_date": days_ago(1),
}

with DAG(
    dag_id="who_triggered_me_mwaa",
    default_args=default_args,
    schedule_interval=None,
    catchup=False,
) as dag:

    task_print_user = PythonOperator(
        task_id="print_triggering_user",
        python_callable=print_trigger_user,
        provide_context=True,
    )
