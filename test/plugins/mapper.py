from dataclasses import dataclass


@dataclass
class WorkItemWrapper:
    state: str
    area: str


def filter_findings():
    pass

def transform_work_item_wrapper(work_item_wrapper: WorkItemWrapper):
    pass
