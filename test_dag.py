from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago

def hello():
    print("Hello from MWAA!")

with DAG(
    dag_id="test_hello_mwaa",
    start_date=days_ago(1),
    schedule_interval=None,
    catchup=False,
) as dag:

    task = PythonOperator(
        task_id="say_hello",
        python_callable=hello
    )
