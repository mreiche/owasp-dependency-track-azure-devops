from azure.devops.released.work_item_tracking import WorkItemTrackingClient
from azure.devops.v7_1.work_item_tracking import WorkItem
from owasp_dt import AuthenticatedClient
from owasp_dt.models import Finding

from owasp_dt_sync import dependency_track, azure, config, models, sync


def test_render_work_item(
        owasp_dt_client: AuthenticatedClient,
        work_item_tracking_client: WorkItemTrackingClient,
        azure_project: str,
        findings: list[Finding],
        azure_work_item_type: str,
):
    finding = findings[1]
    issue = models.Issue(
        "New Finding",
        config.getenv("AZURE_WORK_ITEM_DEFAULT_AREA_PATH"),
        data=models.IssueData(findings=[finding]),
    )
    analysis = dependency_track.get_analysis(owasp_dt_client, finding)
    opt_url = dependency_track.read_azure_devops_work_item_url(analysis)
    if opt_url.absent:
        work_item: WorkItem = work_item_tracking_client.create_work_item(document=issue.create_work_item_document(), project=azure_project, type=azure_work_item_type)
        analysis = dependency_track.create_azure_devops_work_item_analysis(finding, work_item.url)
        dependency_track.add_analysis(owasp_dt_client, analysis)
    else:
        work_item_id = azure.read_work_item_id(opt_url.get())
        work_item_tracking_client.update_work_item(id=work_item_id, document=issue.create_work_item_document(), project=azure_project)


def test_sync_status(
        owasp_dt_client: AuthenticatedClient,
        work_item_tracking_client: WorkItemTrackingClient,
        azure_project: str,
        findings: list[Finding],
        azure_work_item_type: str,
):
    finding = findings[1]
    issue = models.create_issue_from_findings(findings)
    sync.sync_finding(
        owasp_dt_client,
        work_item_tracking_client,
        azure_project,
        azure_work_item_type,
        finding,
        issue
    )
