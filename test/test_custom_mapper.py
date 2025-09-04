from pathlib import Path

from owasp_dt import AuthenticatedClient
from owasp_dt.models import Finding
from tinystream import Stream

from owasp_dt_sync import models, globals

def test_filter_findings(owasp_dt_client: AuthenticatedClient, findings: list[Finding]):
    models.load_custom_mapper_module(Path("plugins/mapper.py"))
    assert len(findings) > 0
    processed_findings = Stream(findings).filter(globals.mapper.process_finding).collect()
    assert len(processed_findings) == 6
