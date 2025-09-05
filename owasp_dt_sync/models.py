import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Callable

from azure.devops.v7_0.core import JsonPatchOperation
from azure.devops.v7_1.work import WorkItem
from owasp_dt.models import Finding, AnalysisRequest, AnalysisRequestAnalysisState, AnalysisRequestAnalysisJustification, AnalysisAnalysisResponse, AnalysisRequestAnalysisResponse, Analysis, AnalysisAnalysisState, AnalysisAnalysisJustification
from tinystream import Opt

from owasp_dt_sync import jinja, log


class WorkItemField(StrEnum):
    TITLE = "System.Title"
    DESCRIPTION = "System.Description"
    AREA = "System.AreaPath"
    STATE = "System.State"
    CHANGED_DATE = "System.ChangedDate"
    REASON = "System.Reason"

    @property
    def field_path(self):
        return f"/fields/{self.value}"

def create_finding_logger(finding: Finding):
    return log.get_logger(
        project=f"{finding.component.project_name}:{finding.component.project_version if isinstance(finding.component.project_version, str) else None}",
        component=f"{finding.component.name}:{finding.component.version}",
        vulnerability=finding.vulnerability.vuln_id,
    )

class WorkItemAdapter:
    def __init__(self, work_item: WorkItem, finding: Finding = None):
        self.__work_item = work_item
        self.__operations: dict[str, JsonPatchOperation] = {}
        self.__finding = finding
        self.work_item_type = ""

    def __opt_field_value(self, field: WorkItemField) -> Opt:
        return Opt(self.__work_item.fields).kmap(field.value)

    def __set_field_value(self, field: WorkItemField, value: any):
        if not self.__work_item.fields:
            self.__work_item.fields = {}

        self.set_field(field.value, value)

    def __get_field_path(self, field: str):
        return f"/fields/{field}"

    def set_field(self, field_name:str, value: any):
        self.__work_item.fields[field_name] = value
        self.__operations[field_name] = JsonPatchOperation(op="add", path=self.__get_field_path(field_name), value=value)

    def get_field(self, field_name: str) -> str|object:
        return Opt(self.__work_item.fields).kmap(field_name).get("")

    @property
    def finding(self):
        return self.__finding

    @property
    def owasp_dt_project_url(self):
        return f"{os.getenv("OWASP_DTRACK_URL")}/projects/{self.finding.component.project}"

    @property
    def work_item(self):
        return self.__work_item

    def set_work_item(self, work_item: WorkItem):
        self.__work_item = work_item
        self.__operations.clear()

    @property
    def title(self) -> str:
        return self.__opt_field_value(WorkItemField.TITLE).get()

    @title.setter
    def title(self, value: str):
        self.__set_field_value(WorkItemField.TITLE, value)

    @property
    def state(self) -> str:
        return self.__opt_field_value(WorkItemField.STATE).get("New")

    @state.setter
    def state(self, value: str):
        if self.state != value:
            self.__set_field_value(WorkItemField.STATE, value)

    @property
    def area(self) -> str:
        return self.__opt_field_value(WorkItemField.AREA).get("")

    @area.setter
    def area(self, value: str):
        if self.area != value:
            self.__set_field_value(WorkItemField.AREA, value)

    @property
    def description(self) -> str:
        return self.__opt_field_value(WorkItemField.DESCRIPTION).get()

    @description.setter
    def description(self, value: str):
        self.__set_field_value(WorkItemField.DESCRIPTION, value)

    @property
    def changed_date(self) -> datetime:
        field_value = self.__opt_field_value(WorkItemField.CHANGED_DATE)
        if field_value.present:
            return field_value.map(datetime.fromisoformat).get()
        else:
            return datetime.fromtimestamp(0, tz=timezone.utc)

    def get_changes(self):
        return list(self.__operations.values())

    def render_description(self):
        self.description = jinja.get_template().render(work_item_adapter=self)


class AnalysisAdapter:
    def __init__(self, analysis: Analysis, finding: Finding):
        self.__analysis = analysis
        self.__analysis_request = AnalysisRequest(project=finding.component.project, component=finding.component.uuid, vulnerability=finding.vulnerability.uuid)

    @property
    def state(self) -> str:
        return Opt(self.__analysis).map_keys("analysis_state", "value").get("")

    @state.setter
    def state(self, value: str):
        if self.state != value:
            self.__analysis.analysis_state = AnalysisAnalysisState(value.upper())
            self.__analysis_request.analysis_state = AnalysisRequestAnalysisState(value.upper())

    @property
    def justification(self) -> str:
        return Opt(self.__analysis).map_keys("analysis_justification", "value").get("")

    @justification.setter
    def justification(self, value: str):
        if self.justification != value:
            self.__analysis.analysis_justification = AnalysisAnalysisJustification(value.upper())
            self.__analysis_request.analysis_justification = AnalysisRequestAnalysisJustification(value.upper())

    @property
    def response(self) -> str:
        return Opt(self.__analysis).map_keys("analysis_response", "value").get("")

    @response.setter
    def response(self, value: str):
        if self.response != value:
            self.__analysis.analysis_response = AnalysisAnalysisResponse(value.upper())
            self.__analysis_request.analysis_response = AnalysisRequestAnalysisResponse(value.upper())

    @property
    def details(self) -> str:
        return Opt(self.__analysis).kmap("analysis_details").filter_type(str).get("")

    @details.setter
    def details(self, value: str):
        if self.details != value:
            self.__analysis.analysis_details = value
            self.__analysis_request.analysis_details = value

    @property
    def suppressed(self) -> bool:
        return Opt(self.__analysis).kmap("is_suppressed").filter_type(bool).get(False)

    @suppressed.setter
    def suppressed(self, value: bool):
        self.__analysis.is_suppressed = value
        self.__analysis_request.is_suppressed = value

    def get_request(self):
        return self.__analysis_request


@dataclass
class MapperModule:
    process_finding: Callable[[Finding], bool]
    new_work_item: Callable[[WorkItemAdapter], None]
    map_work_item_to_analysis: Callable[[WorkItemAdapter, AnalysisAdapter], None]
    map_analysis_to_work_item: Callable[[AnalysisAdapter, WorkItemAdapter], None]
    function_names = ["process_finding", "new_work_item", "map_work_item_to_analysis", "map_analysis_to_work_item"]
