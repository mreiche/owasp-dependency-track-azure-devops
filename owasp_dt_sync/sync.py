from datetime import datetime, timezone

import dotenv
from azure.devops.released.work_item_tracking import WorkItemTrackingClient, WorkItem
from is_empty import empty
from owasp_dt import AuthenticatedClient
from owasp_dt.api.analysis import update_analysis
from owasp_dt.models import Finding, Analysis, AnalysisRequest, AnalysisRequestAnalysisState

from owasp_dt_sync import owasp_dt_helper, azure_helper, models, config, log
from owasp_dt_sync.models import WorkItemWrapper


def handle_sync(args):
    config.apply_changes = args.apply

    if args.env:
        dotenv.load_dotenv(args.env)

    if not config.apply_changes:
        log.logger.info("Running in dry-run mode")

    azure_connection = azure_helper.create_connection_from_env()
    work_item_tracking_client = azure_connection.clients.get_work_item_tracking_client()
    azure_project = config.reqenv("AZURE_PROJECT")
    owasp_dt_client = owasp_dt_helper.create_client_from_env()
    findings = owasp_dt_helper.load_and_filter_findings(
        owasp_dt_client,
        cvss2_min_score=args.cvss_min_score,
        cvss3_min_score=args.cvss_min_score,
    )
    for finding in findings:
        logger = log.get_logger(
            project=f"{finding.component.project_name}:{finding.component.project_version if isinstance(finding.component.project_version, str) else None}",
            component=f"{finding.component.name}:{finding.component.version}",
            vulnerability=finding.vulnerability.vuln_id,
        )
        sync_finding(
            logger,
            owasp_dt_client,
            work_item_tracking_client,
            azure_project,
            finding,
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
    finding: Finding,
):
    analysis = owasp_dt_helper.get_analysis(owasp_dt_client, finding)
    opt_url = owasp_dt_helper.read_azure_devops_work_item_url(analysis)
    if opt_url.absent:
        work_item_wrapper = models.create_new_work_item_wrapper([finding])
        work_item_wrapper.render_description()
        if empty(work_item_wrapper.work_item_type):
            work_item_type = azure_helper.find_best_work_item_type(work_item_tracking_client, azure_project)
            work_item_wrapper.work_item_type = work_item_type.reference_name
        changes = work_item_wrapper.changes
        if config.apply_changes:
            work_item: WorkItem = work_item_tracking_client.create_work_item(document=changes, project=azure_project, type=work_item_wrapper.work_item_type)
            work_item_wrapper.update_work_item(work_item)
            analysis = owasp_dt_helper.create_azure_devops_work_item_analysis(finding, work_item.url)
            owasp_dt_helper.add_analysis(owasp_dt_client, analysis)
            logger = log.get_logger(logger, work_item=work_item_wrapper.work_item.id)
            logger.info(f"Created new WorkItem type '{work_item_wrapper.work_item_type}'")
        else:
            logger.info(f"Would create WorkItem type '{work_item_wrapper.work_item_type}': {azure_helper.pretty_changes(changes)}")
            logger = log.get_logger(logger, work_item=None)
            work_item_wrapper.update_work_item(WorkItem())
    else:
        work_item_id = azure_helper.read_work_item_id(opt_url.get())
        work_item: WorkItem = work_item_tracking_client.get_work_item(id=work_item_id, project=azure_project)
        work_item_wrapper = models.WorkItemWrapper(work_item, [finding])
        logger = log.get_logger(logger, work_item=work_item.id)

    sync_items(
        logger,
        owasp_dt_client,
        work_item_tracking_client,
        azure_project,
        work_item_wrapper,
        finding,
        analysis
    )

def sync_items(
    logger: log.Logger,
    owasp_dt_client: AuthenticatedClient,
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
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
            work_item_wrapper,
            reference_date,
        )
    elif isinstance(newer, WorkItemWrapper):
        sync_work_item_to_finding(
            logger,
            work_item_tracking_client,
            azure_project,
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
    work_item_wrapper: WorkItemWrapper,
    owasp_dt_client: AuthenticatedClient,
    finding: Finding,
    analysis: Analysis,
    reference_date: datetime,
):
    analysis_request = map_work_item_to_analysis_request(work_item_wrapper, finding)
    if config.apply_changes:
        logger.info(f"Update Analysis")
        resp = update_analysis.sync_detailed(client=owasp_dt_client, body=analysis_request)
        assert resp.status_code == 200
    else:
        logger.info(f"Would update Analysis: {owasp_dt_helper.pretty_analysis_request(analysis_request)}")

def sync_finding_to_work_item(
    logger: log.Logger,
    owasp_dt_client: AuthenticatedClient,
    finding: Finding,
    analysis: Analysis,
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
    work_item_wrapper: WorkItemWrapper,
    reference_date: datetime,
):
    work_item_wrapper = map_analysis_to_work_item_wrapper(analysis, work_item_wrapper)
    models.transform_work_item_wrapper(work_item_wrapper)
    changes = work_item_wrapper.changes
    if len(changes) > 0:
        if config.apply_changes:
            logger.info(f"Update WorkItem")
            work_item_tracking_client.update_work_item(id=work_item_wrapper.work_item.id, document=changes, project=azure_project)
        else:
            logger.info(f"Would update WorkItem with the changes: {azure_helper.pretty_changes(changes)}")

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
