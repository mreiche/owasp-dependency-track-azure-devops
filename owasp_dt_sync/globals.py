from pathlib import Path

from owasp_dt_sync import models

apply_changes: bool = False
custom_mapper: models.MapperModule = models.null_mapper
template_path: Path = Path(__file__).parent / "templates/work_item.html.jinja2"
fix_references: bool = False
