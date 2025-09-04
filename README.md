# OWASP Dependency Track / Azure DevOps Sync

Synchronizes OWASP Dependency Track *Findings* with Azure DevOps *WorkItems*.

## Usage

If you configured the [environment variables](#environment-variables), the following command will log possible change operations.
```shell
owasp_dt_sync
```

And run the command to perform these changes.
```shell
owasp_dt_sync --apply
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
```

## Templating

The *WorkItem* description is being rendered by the [provided template](owasp_dt_sync/templates/work_item.html.jinja2).
You can pass your own template using
```shell
owasp_dt_sync --template path/to/your/template.jinja2
```

## Custom filtering and mapping

You can filter findings and apply changes on the work items using custom mappers:
```python
def process_finding(finding):
    return True

def update_work_item_wrapper(work_item_wrapper):
    work_item_wrapper.title = "New Finding"
    if work_item_wrapper.findings[0].component.project_name == "Other project":
        work_item_wrapper.area = "Path\\To\\My\\Custom\\Area"
    pass
```
and pass this mapper using:
```shell
owasp_dt_sync --mapper path/to/your/mapper.py
```
