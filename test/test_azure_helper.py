import pandas as pd
from azure.devops.released.pipelines import PipelinesClient, Pipeline
from azure.devops.released.work_item_tracking import WorkItemTrackingClient
from azure.devops.v7_0.work_item_tracking import JsonPatchOperation
from azure.devops.v7_1.pipelines import Run
from azure.devops.v7_1.work_item_tracking import WorkItem
from is_empty import empty
from datetime import datetime, timedelta

from owasp_dt_sync import azure_helper, config


def test_find_preferred_work_item_type(work_item_tracking_client: WorkItemTrackingClient, azure_project: str):
    type = azure_helper.find_best_work_item_type(work_item_tracking_client, azure_project)
    pass

def test_mask_area_path():
    given_area_path = config.getenv("AZURE_WORK_ITEM_DEFAULT_AREA_PATH")
    assert "\\\\" not in given_area_path
    area_path = azure_helper.mask_area_path(given_area_path)
    assert "\\\\" in area_path
    print(area_path)

def test_read_work_item_id():
    assert azure_helper.read_work_item_id("https://azure.devops.com/abce/_apis/wit/workItems/16142") == 16142

def test_create_and_destroy_work_item(
        work_item_tracking_client: WorkItemTrackingClient,
        azure_project: str
):
    area_path = azure_helper.mask_area_path(config.getenv("AZURE_WORK_ITEM_DEFAULT_AREA_PATH"))
    # https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/create?view=azure-devops-rest-7.1&tabs=HTTP
    document: list[JsonPatchOperation] = [
        JsonPatchOperation(op="add", path="/fields/System.Title", value="Test ticket"),
        JsonPatchOperation(op="add", path="/fields/System.Description", value="This is a test"),
        JsonPatchOperation(op="add", path="/fields/System.AreaPath", value=area_path),
    ]
    work_item_type = azure_helper.find_best_work_item_type(work_item_tracking_client, azure_project)
    work_item: WorkItem = work_item_tracking_client.create_work_item(document=document, project=azure_project, type=work_item_type.reference_name)
    assert not empty(work_item.id)

    work_item_tracking_client.delete_work_item(id=work_item.id, project=azure_project)
    #work_item_tracking_client.destroy_work_item(id=work_item.id, project=azure_project)  # does not work

def test_get_pipeline_runtimes(azure_connection, azure_project: str):
    import pandas as pd
    import matplotlib.pyplot as plt

    pipelines_client: PipelinesClient = azure_connection.clients.get_pipelines_client()
    pipelines: list[Pipeline] = pipelines_client.list_pipelines(project=azure_project)

    data: list[dict] = []

    for pipeline in pipelines:
        pipeline_runs: list[Run] = pipelines_client.list_runs(project=azure_project, pipeline_id=pipeline.id)
        for pipeline_run in pipeline_runs:
            if isinstance(pipeline_run.created_date, datetime) and isinstance(pipeline_run.finished_date, datetime):
                duration = pipeline_run.finished_date - pipeline_run.created_date

                if duration > timedelta(hours=1):
                    continue

                data.append({
                    "name": pipeline.name,
                    "duration": duration
                })

    df = pd.DataFrame(data)
    #df.plot()
    #df["duration"] = pd.to_timedelta(df["duration"], unit="m")
    medians = (df
               .groupby("name")["duration"]
               .median()
               .sort_values(ascending=False)
               .head(50)
               )

    medians_minutes = medians.dt.total_seconds() / 60
    medians_minutes.plot(kind="bar", figsize=(12,6))

    plt.ylabel("min")
    plt.title("Pipeline runtime medians")
    plt.tight_layout()
    plt.show()

    totals = df.groupby("name")["duration"].sum().sort_values(ascending=False).head(50)
    totals = totals.dt.total_seconds() / 60
    totals.plot(kind="bar", figsize=(12,6))
    plt.ylabel("min")
    plt.title("Total pipeline runtime")
    plt.tight_layout()
    plt.show()
