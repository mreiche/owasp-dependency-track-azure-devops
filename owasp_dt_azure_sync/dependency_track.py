from azure.devops.v7_1.work_item_tracking import WorkItem
from is_empty import not_empty
from owasp_dt.api.analysis import update_analysis, retrieve_analysis
from owasp_dt.api.finding import get_all_findings_1
from owasp_dt import Client, AuthenticatedClient
from owasp_dt.models import Finding, AnalysisRequest, Analysis, AnalysisComment
from tinystream import Stream, Opt

from owasp_dt_azure_sync import dependency_track, azure, config


__AZURE_DEVOPS_WORK_ITEM_PREFIX="Azure DevOps work item: "

def create_client_from_env() -> AuthenticatedClient:
    client = Client(
        base_url=config.reqenv("OWASP_DTRACK_URL"),
        headers={
            "X-Api-Key": config.reqenv("OWASP_DTRACK_API_KEY")
        },
        verify_ssl=config.getenv("OWASP_DTRACK_VERIFY_SSL", "1", config.parse_true),
        raise_on_unexpected_status=False,
        httpx_args={
            "proxy": config.getenv("HTTPS_PROXY", lambda: config.getenv("HTTP_PROXY", None)),
            #"no_proxy": getenv("NO_PROXY", "")
        }
    )
    return client

# PUT http://localhost:8081/api/v1/analysis (comment)

def load_and_filter_findings(
        client: AuthenticatedClient,
        cvss2_min_score: float = 0,
        cvss3_min_score: float = 0,
) -> list[Finding]:
    resp = get_all_findings_1.sync_detailed(
        client=client,
        show_inactive=False,
        show_suppressed=False,
        cvssv_2_from=str(cvss2_min_score) if cvss2_min_score > 0 else None,
        cvssv_3_from=str(cvss3_min_score) if cvss3_min_score > 0 else None,
    )
    assert resp.status_code == 200
    return resp.parsed


def finding2str(finding: Finding):
    return f"{finding.component.project_name}:{finding.component.project_version};{finding.component.name}:{finding.component.version};{finding.vulnerability.vuln_id}"

def finding_is_latest(finding: Finding):
    return finding.component.additional_properties["projectVersion"] == finding.component.additional_properties["latestVersion"]

def create_analysis(finding: Finding):
    return AnalysisRequest(
        project=finding.component.project,
        component=finding.component.uuid,
        vulnerability=finding.vulnerability.uuid
    )

def create_azure_devops_work_item_analysis(finding: Finding, url: str):
    analysis = create_analysis(finding)
    analysis.comment = f"{__AZURE_DEVOPS_WORK_ITEM_PREFIX}{url}"
    return analysis

def read_azure_devops_work_item_url(analysis: Analysis):
    return (
        find_comment_prefix(analysis, __AZURE_DEVOPS_WORK_ITEM_PREFIX)
            .map(lambda comment: comment.comment.replace(__AZURE_DEVOPS_WORK_ITEM_PREFIX, ""))
            .filter(not_empty)
    )

def add_analysis(client: AuthenticatedClient, analysis_request: AnalysisRequest):
    resp = update_analysis.sync_detailed(client=client, body=analysis_request)
    assert resp.status_code == 200

def find_comment_prefix(analysis: Analysis, prefix: str):
    def _find_comment(comment: AnalysisComment):
        return comment.comment.startswith(prefix)

    return Stream(analysis.analysis_comments).find(_find_comment)

# def strip_prefix(opt_comment: Opt[AnalysisComment], prefix: str):
#     return comment.comment.replace(prefix, "")

def get_analysis(client: AuthenticatedClient, finding: Finding):
    resp = retrieve_analysis.sync_detailed(client=client, project=finding.component.project, component=finding.component.uuid, vulnerability=finding.vulnerability.uuid)
    assert resp.status_code == 200
    return resp.parsed
