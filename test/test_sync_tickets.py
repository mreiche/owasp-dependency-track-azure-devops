from azure.devops.released.work_item_tracking import WorkItemTrackingClient, WorkItem
from is_empty import empty
from owasp_dt import AuthenticatedClient
from owasp_dt.models import Finding

from owasp_dt_sync import owasp_dt_helper, azure_helper, models, sync, log, globals


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
        work_item_wrapper = sync.create_new_work_item_wrapper(
            work_item_tracking_client=work_item_tracking_client,
            azure_project=azure_project,
            finding=finding,
        )
        work_item_wrapper.render_description()
        if empty(work_item_wrapper.work_item_type):
            work_item_type = azure_helper.find_best_work_item_type(work_item_tracking_client, azure_project)
            work_item_wrapper.work_item_type = work_item_type.reference_name
        work_item: WorkItem = work_item_tracking_client.create_work_item(document=work_item_wrapper.changes, project=azure_project, type=work_item_wrapper.work_item_type)
        work_item_wrapper.update_work_item(work_item)
        analysis = owasp_dt_helper.create_azure_devops_work_item_analysis(finding, work_item.url)
        owasp_dt_helper.add_analysis(owasp_dt_client, analysis)
    else:
        work_item_id = azure_helper.read_work_item_id(opt_url.get())
        work_item_wrapper = models.WorkItemWrapper(WorkItem(id=work_item_id), finding)
        work_item_wrapper.render_description()
        work_item_tracking_client.update_work_item(id=work_item_id, document=work_item_wrapper.changes, project=azure_project)

    log.logger.info(f"Updated work item: {work_item_wrapper.work_item.id}")

def test_sync_status(
        owasp_dt_client: AuthenticatedClient,
        work_item_tracking_client: WorkItemTrackingClient,
        azure_project: str,
        findings: list[Finding],
):
    finding = findings[0]

    globals.apply_changes = True
    globals.fix_references = True

    sync.sync_finding(
        log.logger,
        owasp_dt_client,
        work_item_tracking_client,
        azure_project,
        finding,
    )
