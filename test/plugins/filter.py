from owasp_dt_sync import models

def process_finding(finding):
    return (
            finding.component.name == "urllib3"
            and finding.component.version == "2.4.0"
            and finding.component.project_name == "test-project"
            and finding.component.project_version == "latest"
    )


def new_work_item(work_item_adapter: models.WorkItemAdapter):
    work_item_adapter.render_description()
