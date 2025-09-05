import random
from typing import Iterator

from owasp_dt import AuthenticatedClient
from owasp_dt.api.analysis import update_analysis, retrieve_analysis
from owasp_dt.models import AnalysisRequest, Finding
from tinystream import Stream

from owasp_dt_sync import owasp_dt_helper


def test_add_findings_comment(owasp_dt_client: AuthenticatedClient, findings: Iterator[Finding]):
    finding = next(findings)

    test_comment = f"TestComment {random.randrange(0, 9999)}"
    analysis_request = AnalysisRequest(project=finding.component.project, component=finding.component.uuid, vulnerability=finding.vulnerability.uuid, comment=test_comment)
    resp = update_analysis.sync_detailed(client=owasp_dt_client, body=analysis_request)
    assert resp.status_code == 200

    resp = retrieve_analysis.sync_detailed(client=owasp_dt_client, project=finding.component.project, component=finding.component.uuid, vulnerability=finding.vulnerability.uuid)
    assert resp.status_code == 200

    analysis = resp.parsed
    assert Stream(analysis.analysis_comments).filter(lambda comment: test_comment in comment.comment).next().present


def test_add_work_item_url(owasp_dt_client: AuthenticatedClient, findings: Iterator[Finding]):
    finding = next(findings)

    test_url = f"http://test/item/{random.randrange(0, 9999)}"
    analysis = owasp_dt_helper.create_azure_devops_work_item_analysis(finding, test_url)
    owasp_dt_helper.add_analysis(owasp_dt_client, analysis)
    analysis = owasp_dt_helper.get_analysis(owasp_dt_client, finding)
    opt_url = owasp_dt_helper.read_azure_devops_work_item_url(analysis)
    assert opt_url.present
    assert opt_url.get() == test_url
