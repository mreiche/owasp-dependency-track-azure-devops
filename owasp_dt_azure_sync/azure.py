import re

from azure.devops.connection import Connection
from is_empty import empty
from msrest.authentication import BasicAuthentication
from owasp_dt import Client
from owasp_dt.models import Finding

from owasp_dt_azure_sync import config


def create_connection_from_env() -> Connection:
    credentials = BasicAuthentication('', config.reqenv("AZURE_API_KEY"))
    return Connection(base_url=config.reqenv("AZURE_ORG_URL"), creds=credentials)

def sync_finding(owasp_dt_client: Client, finding: Finding):
    pass
    #retrieve_analysis.sync(owasp_dt_client, project=finding.p)
    #/v1/analysis

def mask_area_path(area_path: str):
    return area_path.replace("\\", "\\\\")

__work_item_id_regex = re.compile("workItems/(\\d+)")

def read_work_item_id(url: str) -> int:
    matches = __work_item_id_regex.search(url)
    found = matches.group(1)
    assert not empty(found)
    work_item_id = int(found)
    assert work_item_id > 0
    return work_item_id
