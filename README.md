# OWASP Dependency Track / Azure DevOps Sync

Synchronizes OWASP Dependency Track *Findings* with Azure DevOps *WorkItems*.

## Usage

The following command will log possible change operations, when the [environment variables](#environment-variables) are configured:
```shell
owasp-dtrack-azure-devops
```

Use the following flag to perform these changes:
```shell
owasp-dtrack-azure-devops --apply
```

## Environment variables

You can also pass these variables in a file using the `--env` parameter.

```shell
AZURE_ORG_URL="https://dev.azure.com/organisation"  # Azure organisation URL
AZURE_PROJECT=""                                    # Azure project name
AZURE_API_KEY=""                                    # Azure API key to use (PAT also works)
AZURE_WORK_ITEM_DEFAULT_AREA_PATH="My\Path"         # The default area path for new work items (recommended)
OWASP_DTRACK_URL="http://localhost:8081"            # Base-URL to OWASP Dependency Track
OWASP_DTRACK_VERIFY_SSL="False"                     # Do not verify SSL
OWASP_DTRACK_API_KEY=""                             # Your OWASP Dependency Track API Key
HTTPS_PROXY=""                                      # URL for HTTP(S) proxy (optional)
LOG_LEVEL="info"                                    # Logging verbosity (optional)
HTTPX_LOG_LEVEL="warning"                           # Log level of the httpx framework (optional)
```

## Templating

The *WorkItem* description is being rendered by the [provided template](owasp_dt_sync/templates/work_item.html.jinja2).
You can pass your own template using
```shell
owasp-dtrack-azure-devops --template path/to/your/template.jinja2
```

## Custom filtering and mapping

You can filter findings and apply changes on the work items using custom mappers:

```python
def process_finding(finding):
    return finding.component.project_name == "My_Project"

def new_work_item(work_item_adapter):
    work_item_adapter.title = "New Finding"

    if work_item_adapter.finding.component.project_name == "Other project":
        work_item_adapter.area = "Path\\To\\My\\Custom\\Area"
        
def map_analysis_to_work_item(analysis_adapter, work_item_adapter):
    # Call this method if you want to re-render the ticket description
    work_item_adapter.render_description()

# Remove mappers you don't need
# def map_work_item_to_analysis(work_item_adapter, analysis_adapter):
#     pass
```
and pass this mapper using:
```shell
owasp-dtrack-azure-devops --mapper path/to/your/mapper.py
```
