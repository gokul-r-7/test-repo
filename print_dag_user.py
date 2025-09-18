from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago
from airflow.utils.db import create_session
from airflow.models.log import Log

def print_trigger_user(**context):
    dag_run = context.get('dag_run')
    if not dag_run:
        print("No dag_run in context; cannot find triggering user.")
        return

    dag_id = dag_run.dag_id
    exec_date = dag_run.execution_date

    with create_session() as session:
        log_entry = (
            session.query(Log)
            .filter(
                Log.dag_id == dag_id,
                Log.event == "trigger",
                Log.execution_date == exec_date
            )
            .order_by(Log.dttm.desc())
            .first()
        )
        if log_entry:
            print(f"DAG {dag_id} was triggered by user: {log_entry.owner}")
        else:
            print(f"No trigger log entry found for DAG {dag_id} at execution_date {exec_date}")

default_args = {
    "owner": "airflow",
    "start_date": days_ago(1),
}

with DAG(
    dag_id="who_triggered_me",
    default_args=default_args,
    schedule_interval=None,
    catchup=False,
) as dag:

    task = PythonOperator(
        task_id="print_trigger_user",
        python_callable=print_trigger_user,
        # do NOT use provide_context=True in Airflow 2+
    )
