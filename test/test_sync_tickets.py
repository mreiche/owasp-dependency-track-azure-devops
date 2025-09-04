from azure.devops.released.work_item_tracking import WorkItemTrackingClient, WorkItem
from is_empty import empty
from owasp_dt import AuthenticatedClient
from owasp_dt.models import Finding

from owasp_dt_sync import owasp_dt_helper, azure_helper, models, sync, log


def test_render_work_item(
        owasp_dt_client: AuthenticatedClient,
        work_item_tracking_client: WorkItemTrackingClient,
        azure_project: str,
        findings: list[Finding],
):
    finding = findings[1]
    analysis = owasp_dt_helper.get_analysis(owasp_dt_client, finding)
    opt_url = owasp_dt_helper.read_azure_devops_work_item_url(analysis)
    if opt_url.absent:
        work_item_wrapper = models.create_new_work_item_wrapper([finding])
        work_item_wrapper.render_description()
        if empty(work_item_wrapper.work_item_type):
            work_item_type = azure_helper.find_best_work_item_type(work_item_tracking_client, azure_project)
            work_item_wrapper.work_item_type = work_item_type.reference_name
        work_item: WorkItem = work_item_tracking_client.create_work_item(document=work_item_wrapper.changes, project=azure_project, type=work_item_wrapper.work_item_type)
        analysis = owasp_dt_helper.create_azure_devops_work_item_analysis(finding, work_item.url)
        owasp_dt_helper.add_analysis(owasp_dt_client, analysis)
    else:
        work_item_id = azure_helper.read_work_item_id(opt_url.get())
        work_item_wrapper = models.WorkItemWrapper(WorkItem(), [finding])
        work_item_wrapper.render_description()
        work_item_tracking_client.update_work_item(id=work_item_id, document=work_item_wrapper.changes, project=azure_project)


def test_sync_status(
        owasp_dt_client: AuthenticatedClient,
        work_item_tracking_client: WorkItemTrackingClient,
        azure_project: str,
        findings: list[Finding],
        azure_work_item_type: str,
):
    finding = findings[1]
    sync.sync_finding(
        log.logger,
        owasp_dt_client,
        work_item_tracking_client,
        azure_project,
        azure_work_item_type,
        finding,
    )
