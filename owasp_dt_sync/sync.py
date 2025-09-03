from datetime import datetime, timezone

import dotenv
from azure.devops.released.work_item_tracking import WorkItemTrackingClient
from azure.devops.v7_0.work import WorkItem
from owasp_dt import AuthenticatedClient
from owasp_dt.api.analysis import update_analysis
from owasp_dt.models import Finding, Analysis, AnalysisRequest, AnalysisRequestAnalysisState

from owasp_dt_sync import owasp_dt_helper, azure_helper, models, config, log
from owasp_dt_sync.models import WorkItemWrapper


def handle_sync(args):
    config.apply_changes = args.apply

    if args.env:
        dotenv.load_dotenv(args.env)

    azure_connection = azure_helper.create_connection_from_env()
    work_item_tracking_client = azure_connection.clients.get_work_item_tracking_client()
    azure_project = config.reqenv("AZURE_PROJECT")
    azure_work_item_type = config.reqenv("AZURE_WORK_ITEM_TYPE")
    owasp_dt_client = owasp_dt_helper.create_client_from_env()
    findings = owasp_dt_helper.load_and_filter_findings(
        owasp_dt_client,
        cvss2_min_score=args.cvss_min_score,
        cvss3_min_score=args.cvss_min_score,
    )
    for finding in findings:
        logger = log.get_logger(
            dry_run=not config.apply_changes,
            project=f"{finding.component.project_name}:{finding.component.project_version}",
            component=f"{finding.component.name}:{finding.component.version}",
            vulnerability=finding.vulnerability.vuln_id,
        )
        issue = models.create_issue_from_findings([finding])
        sync_finding(
            logger,
            owasp_dt_client,
            work_item_tracking_client,
            azure_project,
            azure_work_item_type,
            finding,
            issue,
        )

def find_newer(work_item_wrapper: WorkItemWrapper, analysis: Analysis) -> tuple[WorkItemWrapper | Analysis, datetime]:
    work_item_changed_data = work_item_wrapper.changed_date
    comments = owasp_dt_helper.read_comments(analysis).collect()
    if len(comments) > 0:
        last_comment = comments[-1]
        last_comment_date = owasp_dt_helper.create_date_from_comment(last_comment)
    else:
        last_comment_date = datetime.fromtimestamp(0, tz=timezone.utc)

    if work_item_changed_data > last_comment_date:
        return work_item_wrapper, work_item_changed_data
    else:
        return analysis, last_comment_date

def sync_finding(
    logger: log.Logger,
    owasp_dt_client: AuthenticatedClient,
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
    azure_work_item_type: str,
    finding: Finding,
    issue: models.Issue,
):
    analysis = owasp_dt_helper.get_analysis(owasp_dt_client, finding)
    opt_url = owasp_dt_helper.read_azure_devops_work_item_url(analysis)
    if opt_url.absent:
        logger.info("Create new WorkItem")
        if config.apply_changes:
            work_item: WorkItem = work_item_tracking_client.create_work_item(document=issue.create_work_item_document(), project=azure_project, type=azure_work_item_type)
            analysis = owasp_dt_helper.create_azure_devops_work_item_analysis(finding, work_item.url)
            owasp_dt_helper.add_analysis(owasp_dt_client, analysis)
        else:
            work_item = WorkItem()
    else:
        work_item_id = azure_helper.read_work_item_id(opt_url.get())
        work_item: WorkItem = work_item_tracking_client.get_work_item(id=work_item_id, project=azure_project)

    work_item_wrapper = WorkItemWrapper(work_item)

    sync_items(
        logger,
        owasp_dt_client,
        work_item_tracking_client,
        azure_project,
        azure_work_item_type,
        work_item_wrapper,
        finding,
        analysis
    )

def sync_items(
    logger: log.Logger,
    owasp_dt_client: AuthenticatedClient,
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
    azure_work_item_type: str,
    work_item_wrapper: WorkItemWrapper,
    finding: Finding,
    analysis: Analysis,
):
    newer, reference_date = find_newer(work_item_wrapper, analysis)
    if isinstance(newer, Analysis):
        sync_finding_to_work_item(
            logger,
            owasp_dt_client,
            finding,
            analysis,
            work_item_tracking_client,
            azure_project,
            azure_work_item_type,
            work_item_wrapper,
            reference_date,
        )
    else:
        sync_work_item_to_finding(
            logger,
            work_item_tracking_client,
            azure_project,
            azure_work_item_type,
            work_item_wrapper,
            owasp_dt_client,
            finding,
            analysis,
            reference_date,
        )


def sync_work_item_to_finding(
    logger: log.Logger,
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
    azure_work_item_type: str,
    work_item_wrapper: WorkItemWrapper,
    owasp_dt_client: AuthenticatedClient,
    finding: Finding,
    analysis: Analysis,
    reference_date: datetime,
):
    analysis_request = map_work_item_to_analysis_request(work_item_wrapper, finding)
    logger.info(f"Update Finding analysis")
    if config.apply_changes:
        resp = update_analysis.sync_detailed(client=owasp_dt_client, body=analysis_request)
        assert resp.status_code == 200


def sync_finding_to_work_item(
    logger: log.Logger,
    owasp_dt_client: AuthenticatedClient,
    finding: Finding,
    analysis: Analysis,
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
    azure_work_item_type: str,
    work_item_wrapper: WorkItemWrapper,
    reference_date: datetime,
):
    work_item_wrapper = map_analysis_to_work_item_wrapper(analysis, work_item_wrapper)
    changes = work_item_wrapper.changes
    if len(changes) > 0:
        logger.info(f"Update WorkItem")
        if config.apply_changes:
            work_item_tracking_client.update_work_item(id=work_item_wrapper.work_item.id, document=changes, project=azure_project)

def map_work_item_to_analysis_request(work_item_wrapper: models.WorkItemWrapper, finding: Finding):
    work_item_state = work_item_wrapper.state
    analysis_state = AnalysisRequestAnalysisState.NOT_SET
    suppressed = False
    if work_item_state == models.WorkItemState.ACTIVE:
        analysis_state = AnalysisRequestAnalysisState.IN_TRIAGE
    elif work_item_state == models.WorkItemState.CLOSED:
        analysis_state = AnalysisRequestAnalysisState.RESOLVED
        suppressed = True

    return AnalysisRequest(project=finding.component.project, component=finding.component.uuid, vulnerability=finding.vulnerability.uuid, analysis_state=analysis_state, suppressed=suppressed)


def map_analysis_to_work_item_wrapper(analysis: Analysis, work_item_wrapper: models.WorkItemWrapper):
    work_item_state = models.WorkItemState.NEW
    if analysis.analysis_state in [
        AnalysisRequestAnalysisState.IN_TRIAGE,
        AnalysisRequestAnalysisState.EXPLOITABLE,
    ]:
        work_item_state = models.WorkItemState.ACTIVE
    elif analysis.analysis_state in [
        AnalysisRequestAnalysisState.RESOLVED,
        AnalysisRequestAnalysisState.FALSE_POSITIVE,
        AnalysisRequestAnalysisState.NOT_AFFECTED
    ]:
        work_item_state = models.WorkItemState.CLOSED

    # if analysis.is_suppressed:
    #     work_item_state = WorkItemState.CLOSED

    work_item_wrapper.state = work_item_state
    return work_item_wrapper
