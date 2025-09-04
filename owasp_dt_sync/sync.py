from datetime import datetime, timezone

import dotenv
from azure.devops.exceptions import AzureDevOpsServiceError
from azure.devops.released.work_item_tracking import WorkItemTrackingClient, WorkItem
from is_empty import empty
from owasp_dt import AuthenticatedClient
from owasp_dt.api.analysis import update_analysis
from owasp_dt.models import Finding, Analysis
from tinystream import Stream

from owasp_dt_sync import owasp_dt_helper, azure_helper, models, config, log, globals
from owasp_dt_sync.models import WorkItemWrapper


def handle_sync(args):
    globals.apply_changes = args.apply
    globals.fix_references = args.fix_references

    if not globals.apply_changes:
        log.logger.info("Running in dry-run mode (add --apply parameter to perform changes)")

    if args.template:
        globals.template_path = args.template

    if args.env:
        assert dotenv.load_dotenv(args.env), f"Unable to load env file: '{args.env}'"

    if args.mapper:
        models.load_custom_mapper_module(args.mapper)

    azure_connection = azure_helper.create_connection_from_env()
    work_item_tracking_client = azure_connection.clients.get_work_item_tracking_client()
    azure_project = config.reqenv("AZURE_PROJECT")
    owasp_dt_client = owasp_dt_helper.create_client_from_env()
    findings = owasp_dt_helper.load_and_filter_findings(
        client=owasp_dt_client,
        cvss2_min_score=args.cvss_min_score,
        cvss3_min_score=args.cvss_min_score,
        load_suppressed=args.load_suppressed,
        load_inactive=args.load_inactive,
    )
    for finding in Stream(findings).filter(globals.mapper.process_finding):
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
    comments = owasp_dt_helper.read_comments_desc(analysis).collect()
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
    finding_logger: log.Logger,
    owasp_dt_client: AuthenticatedClient,
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
    finding: Finding,
):
    work_item_logger = finding_logger

    analysis = owasp_dt_helper.get_analysis(owasp_dt_client, finding)
    opt_url = owasp_dt_helper.read_azure_devops_work_item_url(analysis)

    if opt_url.absent:
        work_item_wrapper = create_new_work_item_wrapper(
            work_item_tracking_client=work_item_tracking_client,
            azure_project=azure_project,
            finding=finding,
        )

        if globals.apply_changes:
            work_item_logger, analysis = create_work_item(
                logger=finding_logger,
                work_item_tracking_client=work_item_tracking_client,
                work_item_wrapper=work_item_wrapper,
                azure_project=azure_project,
                owasp_dt_client=owasp_dt_client,
                finding=finding,
            )
        else:
            finding_logger.info(f"Would create WorkItem type '{work_item_wrapper.work_item_type}': {azure_helper.pretty_changes(work_item_wrapper.changes)}")
            work_item_logger = log.get_logger(finding_logger, work_item=None)
            work_item_wrapper.update_work_item(WorkItem())
    else:
        work_item_id = azure_helper.read_work_item_id(opt_url.get())
        work_item_wrapper = models.WorkItemWrapper(WorkItem(id=work_item_id), finding)

        try:
            work_item: WorkItem = work_item_tracking_client.get_work_item(id=work_item_id, project=azure_project)
            work_item_wrapper.update_work_item(work_item)
            work_item_logger = log.get_logger(finding_logger, work_item=work_item_id)
        except AzureDevOpsServiceError as e:
            finding_logger.error(e)
            if globals.fix_references:
                work_item_wrapper = create_new_work_item_wrapper(
                    work_item_tracking_client=work_item_tracking_client,
                    azure_project=azure_project,
                    finding=finding,
                )
                work_item_logger, analysis = create_work_item(
                    logger=finding_logger,
                    work_item_tracking_client=work_item_tracking_client,
                    azure_project=azure_project,
                    work_item_wrapper=work_item_wrapper,
                    owasp_dt_client=owasp_dt_client,
                    finding=finding,
                )

    sync_items(
        logger=work_item_logger,
        owasp_dt_client=owasp_dt_client,
        work_item_tracking_client=work_item_tracking_client,
        azure_project=azure_project,
        work_item_wrapper=work_item_wrapper,
        analysis=analysis
    )

def create_new_work_item_wrapper(
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
    finding: Finding = None
):
    work_item_wrapper = WorkItemWrapper(WorkItem(), finding)
    work_item_wrapper.title = "New Finding"
    work_item_wrapper.area = config.getenv("AZURE_WORK_ITEM_DEFAULT_AREA_PATH", "")
    globals.mapper.new_work_item(work_item_wrapper)
    work_item_wrapper.render_description()

    if empty(work_item_wrapper.work_item_type):
        work_item_type = azure_helper.find_best_work_item_type(work_item_tracking_client, azure_project)
        work_item_wrapper.work_item_type = work_item_type.reference_name

    return work_item_wrapper

def create_work_item(
    logger: log.Logger,
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
    work_item_wrapper: WorkItemWrapper,
    owasp_dt_client: AuthenticatedClient,
    finding: Finding,
):
    work_item: WorkItem = work_item_tracking_client.create_work_item(document=work_item_wrapper.changes, project=azure_project, type=work_item_wrapper.work_item_type)
    work_item_wrapper.update_work_item(work_item)

    analysis = owasp_dt_helper.create_azure_devops_work_item_analysis(finding, work_item.url)
    owasp_dt_helper.add_analysis(owasp_dt_client, analysis)

    logger = log.get_logger(logger, work_item=work_item_wrapper.work_item.id)
    logger.info(f"Created new WorkItem type '{work_item_wrapper.work_item_type}'")

    return logger, analysis

def sync_items(
    logger: log.Logger,
    owasp_dt_client: AuthenticatedClient,
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
    work_item_wrapper: WorkItemWrapper,
    analysis: Analysis,
):
    newer, reference_date = find_newer(work_item_wrapper, analysis)
    analysis_wrapper = models.AnalysisWrapper(analysis, work_item_wrapper.finding)
    if isinstance(newer, Analysis):
        sync_analysis_to_work_item(
            logger=logger,
            owasp_dt_client=owasp_dt_client,
            analysis_wrapper=analysis_wrapper,
            work_item_tracking_client=work_item_tracking_client,
            azure_project=azure_project,
            work_item_wrapper=work_item_wrapper,
            reference_date=reference_date,
        )
    elif isinstance(newer, WorkItemWrapper):
        sync_work_item_to_analysis(
            logger=logger,
            work_item_tracking_client=work_item_tracking_client,
            azure_project=azure_project,
            work_item_wrapper=work_item_wrapper,
            owasp_dt_client=owasp_dt_client,
            analysis_wrapper=analysis_wrapper,
            reference_date=reference_date,
        )


def sync_work_item_to_analysis(
    logger: log.Logger,
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
    work_item_wrapper: WorkItemWrapper,
    owasp_dt_client: AuthenticatedClient,
    analysis_wrapper: models.AnalysisWrapper,
    reference_date: datetime,
):
    globals.mapper.map_work_item_to_analysis(work_item_wrapper, analysis_wrapper)

    if globals.apply_changes:
        logger.info(f"Update Analysis: {owasp_dt_helper.pretty_analysis_request(analysis_wrapper.request)}")
        resp = update_analysis.sync_detailed(client=owasp_dt_client, body=analysis_wrapper.request)
        assert resp.status_code == 200
    else:
        logger.info(f"Would update Analysis: {owasp_dt_helper.pretty_analysis_request(analysis_wrapper.request)}")

def sync_analysis_to_work_item(
    logger: log.Logger,
    owasp_dt_client: AuthenticatedClient,
    analysis_wrapper: models.AnalysisWrapper,
    work_item_tracking_client: WorkItemTrackingClient,
    azure_project: str,
    work_item_wrapper: WorkItemWrapper,
    reference_date: datetime,
):
    globals.mapper.map_analysis_to_work_item(analysis_wrapper, work_item_wrapper)

    changes = work_item_wrapper.changes
    if len(changes) > 0:
        if globals.apply_changes:
            try:
                work_item_tracking_client.update_work_item(id=work_item_wrapper.work_item.id, document=changes, project=azure_project)
                logger.info(f"Updated WorkItem")
            except AzureDevOpsServiceError as e:
                logger.error(e)
        else:
            logger.info(f"Would update WorkItem with the changes: {azure_helper.pretty_changes(changes)}")
