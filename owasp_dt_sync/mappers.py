import importlib.util
from pathlib import Path

from owasp_dt_sync import models, log


def map_work_item_to_analysis(
        work_item_adapter: models.WorkItemAdapter,
        analysis_adapter: models.AnalysisAdapter
):
    analysis_adapter.suppressed = False

    if work_item_adapter.state == "New":
        analysis_adapter.state = "NOT_SET"
    elif work_item_adapter.state in ["Closed", "Removed"]:
        analysis_adapter.state = "RESOLVED"
        analysis_adapter.suppressed = True
    else:
        analysis_adapter.state = "IN_TRIAGE"


def map_analysis_to_work_item(
        analysis_adapter: models.AnalysisAdapter,
        work_item_adapter: models.WorkItemAdapter
):
    if analysis_adapter.state in [
        "IN_TRIAGE",
        "EXPLOITABLE",
    ]:
        work_item_adapter.state = "Active"
    elif analysis_adapter.state in [
        "RESOLVED",
        "FALSE_POSITIVE",
        "NOT_AFFECTED",
    ]:
        work_item_adapter.state = "Closed"
    else:
        work_item_adapter.state = "New"


def new_work_item(work_item_adapter: models.WorkItemAdapter):
    work_item_adapter.render_description()

def load_custom_mapper_module(mapper_path: Path|str):
    from owasp_dt_sync import globals

    if isinstance(mapper_path, Path):
        mapper_path = str(mapper_path)

    spec = importlib.util.spec_from_file_location(mapper_path, mapper_path)
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)

    for function_name in models.MapperModule.function_names:
        mapper_function = getattr(modul, function_name, None)
        if mapper_function:
            assert callable(mapper_function), f"Mapper function '{modul.__name__}:{function_name}' is not callable"
            log.logger.info(f"Connect custom mapper function: '{mapper_path}:{function_name}'")
            globals.mapper.__setattr__(function_name, mapper_function)

default_mapper = models.MapperModule(
    process_finding=lambda x: True,
    new_work_item=new_work_item,
    map_analysis_to_work_item=map_analysis_to_work_item,
    map_work_item_to_analysis=map_work_item_to_analysis,
)
