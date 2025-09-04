# OWASP Dependency Track / Azure DevOps Sync

Synchronizes OWASP Dependency Track Issues with Azure Devops WorkItems.

## Environment variables

```shell
AZURE_ORG_URL="https://dev.azure.com/organisation"  # Azure organisation URL
AZURE_PROJECT=""                                    # Azure project name
AZURE_API_KEY=""                                    # Azure API key to use (PAT also works)
AZURE_WORK_ITEM_DEFAULT_AREA_PATH="My\Path"         # The default area path for new work items
OWASP_DTRACK_URL="http://localhost:8081"            # Base-URL to OWASP Dependency Track (without '/api' as base path)
OWASP_DTRACK_VERIFY_SSL="False"                     # Do not verify SSL
OWASP_DTRACK_API_KEY=""                             # Your OWASP Dependency Track API Key
HTTPS_PROXY=""                                      # URL for HTTP(S) proxy
LOG_LEVEL="info"                                    # Logging verbosity
```
