from datetime import datetime, timezone
from typing import Iterable

from is_empty import not_empty
from owasp_dt import Client, AuthenticatedClient
from owasp_dt.api.analysis import update_analysis, retrieve_analysis
from owasp_dt.api.finding import get_all_findings_1
from owasp_dt.models import Finding, AnalysisRequest, Analysis, AnalysisComment
from tinystream import Stream, Opt

from owasp_dt_sync import config

__AZURE_DEVOPS_WORK_ITEM_PREFIX="Azure DevOps work item: "

def create_client_from_env() -> AuthenticatedClient:
    base_url = config.reqenv("OWASP_DTRACK_URL")
    client = Client(
        base_url=f"{base_url}/api",
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

def pretty_analysis_request(analysis_request: AnalysisRequest):
    req_dict = analysis_request.to_dict()
    for key in ("component", "vulnerability", "project"):
        del req_dict[key]

    return req_dict

def load_findings(
    client: AuthenticatedClient,
    cvss2_min_score: float = 0,
    cvss3_min_score: float = 0,
    load_suppressed: bool = False,
    load_inactive: bool = False,
) -> list[Finding]:
    resp = get_all_findings_1.sync_detailed(
        client=client,
        show_inactive=load_inactive,
        show_suppressed=load_suppressed,
        cvssv_2_from=cvss2_min_score if cvss2_min_score > 0 else None,
        cvssv_3_from=cvss3_min_score if cvss3_min_score > 0 else None,
    )
    assert resp.status_code == 200
    return resp.parsed

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
    def _find(comment: AnalysisComment):
        return comment.comment.startswith(prefix)

    return read_comments_desc(analysis).find(_find)

def read_comments_desc(analysis: Analysis) -> Stream[AnalysisComment]:
    def _sort_oldest_first(a: AnalysisComment, b: AnalysisComment):
        return b.timestamp - a.timestamp

    return (
        Opt(analysis)
        .kmap("analysis_comments")
        .filter_type(Iterable)
        .stream()
        .sort(_sort_oldest_first)
    )

def get_analysis(client: AuthenticatedClient, finding: Finding) -> Analysis:
    resp = retrieve_analysis.sync_detailed(client=client, project=finding.component.project, component=finding.component.uuid, vulnerability=finding.vulnerability.uuid)
    if resp.status_code == 404:
        return Analysis()
    else:
        assert resp.status_code == 200
        return resp.parsed


def create_date_from_comment(comment: AnalysisComment):
    return datetime.fromtimestamp(comment.timestamp/1000, timezone.utc)
