from pathlib import Path

from owasp_dt_sync import mappers

apply_changes: bool = False
mapper = mappers.default_mapper
template_path: Path = Path(__file__).parent / "templates/work_item.html.jinja2"
fix_references: bool = False
