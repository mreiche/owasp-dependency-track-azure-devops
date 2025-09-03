from azure.devops.released.work_item_tracking import WorkItemTrackingClient
from azure.devops.v7_0.work import WorkItem
from azure.devops.v7_1.core import JsonPatchOperation
from owasp_dt import AuthenticatedClient
from owasp_dt.api.analysis import update_analysis
from owasp_dt.models import Finding, Analysis, AnalysisComment, AnalysisRequest, AnalysisRequestAnalysisState
from datetime import datetime
from owasp_dt_azure_sync import dependency_track, azure, config, models
from owasp_dt_azure_sync.models import WorkItemState, WorkItemWrapper


def find_newer(work_item: WorkItem, analysis: Analysis) -> tuple[WorkItem|Analysis, datetime]:
    work_item_changed_data = datetime.fromisoformat(work_item.fields['System.ChangedDate'])
    comments = dependency_track.read_comments(analysis).collect()
    last_comment = comments[-1]
    last_comment_date = dependency_track.create_date_from_comment(last_comment)

    if work_item_changed_data > last_comment_date:
        return work_item, work_item_changed_data
    else:
        return analysis, last_comment_date

def sync_finding(
    owasp_dt_client: AuthenticatedClient,
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
    azure_work_item_type: str,
    finding: Finding,
    issue: models.Issue,
):
    analysis = dependency_track.get_analysis(owasp_dt_client, finding)
    opt_url = dependency_track.read_azure_devops_work_item_url(analysis)
    if opt_url.absent:
        work_item: WorkItem = work_item_tracking_client.create_work_item(document=issue.create_work_item_document(), project=azure_project, type=azure_work_item_type)
        analysis = dependency_track.create_azure_devops_work_item_analysis(finding, work_item.url)
        dependency_track.add_analysis(owasp_dt_client, analysis)
    else:
        work_item_id = azure.read_work_item_id(opt_url.get())
        work_item: WorkItem = work_item_tracking_client.get_work_item(id=work_item_id, project=azure_project)

    sync_items(
        owasp_dt_client,
        work_item_tracking_client,
        azure_project,
        azure_work_item_type,
        work_item,
        finding,
        analysis
    )

def sync_items(
    owasp_dt_client: AuthenticatedClient,
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
    azure_work_item_type: str,
    work_item: WorkItem,
    finding: Finding,
    analysis: Analysis,
):
    newer, reference_date = find_newer(work_item, analysis)
    if isinstance(newer, Analysis):
        sync_finding_to_work_item(
            owasp_dt_client,
            finding,
            analysis,
            work_item_tracking_client,
            azure_project,
            azure_work_item_type,
            work_item,
            reference_date,
        )
    else:
        sync_work_item_to_finding(
            work_item_tracking_client,
            azure_project,
            azure_work_item_type,
            work_item,
            owasp_dt_client,
            finding,
            analysis,
            reference_date,
        )


def sync_work_item_to_finding(
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
    azure_work_item_type: str,
    work_item: WorkItem,
    owasp_dt_client: AuthenticatedClient,
    finding: Finding,
    analysis: Analysis,
    reference_date: datetime,
):
    analysis_request = map_work_item_to_analysis_request(work_item, finding)
    resp = update_analysis.sync_detailed(client=owasp_dt_client, body=analysis_request)
    assert resp.status_code == 200

def sync_finding_to_work_item(
    owasp_dt_client: AuthenticatedClient,
    finding: Finding,
    analysis: Analysis,
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
    azure_work_item_type: str,
    work_item: WorkItem,
    reference_date: datetime,
):
    wrapper = map_analysis_to_work_item_wrapper(analysis, work_item)
    changes = wrapper.changes
    if len(changes) > 0:
        work_item_tracking_client.update_work_item(id=work_item.id, document=changes, project=azure_project)


def map_work_item_to_analysis_request(work_item: WorkItem, finding: Finding):
    wrapper = WorkItemWrapper(work_item)
    work_item_state = wrapper.state
    analysis_state = AnalysisRequestAnalysisState.NOT_SET
    suppressed = False
    if work_item_state == WorkItemState.ACTIVE:
        analysis_state = AnalysisRequestAnalysisState.IN_TRIAGE
    elif work_item_state == WorkItemState.CLOSED:
        analysis_state = AnalysisRequestAnalysisState.RESOLVED
        suppressed = True

    return AnalysisRequest(project=finding.component.project, component=finding.component.uuid, vulnerability=finding.vulnerability.uuid, analysis_state=analysis_state, suppressed=suppressed)


def map_analysis_to_work_item_wrapper(analysis: Analysis, work_item: WorkItem):
    wrapper = WorkItemWrapper(work_item)
    work_item_state = WorkItemState.NEW
    if analysis.analysis_state in [
        AnalysisRequestAnalysisState.IN_TRIAGE,
        AnalysisRequestAnalysisState.EXPLOITABLE,
    ]:
        work_item_state = WorkItemState.ACTIVE
    elif analysis.analysis_state in [
        AnalysisRequestAnalysisState.RESOLVED,
        AnalysisRequestAnalysisState.FALSE_POSITIVE,
        AnalysisRequestAnalysisState.NOT_AFFECTED
    ]:
        work_item_state = WorkItemState.CLOSED

    # if analysis.is_suppressed:
    #     work_item_state = WorkItemState.CLOSED

    wrapper.state = work_item_state
    return wrapper
