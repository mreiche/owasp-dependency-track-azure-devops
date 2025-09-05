from owasp_dt.models import Analysis, AnalysisAnalysisState, AnalysisAnalysisJustification, AnalysisAnalysisResponse, Finding

from owasp_dt_sync import models


def test_analysis_adapter(finding_stub: Finding):
    analysis = Analysis(
        analysis_state=AnalysisAnalysisState.EXPLOITABLE,
        analysis_justification=AnalysisAnalysisJustification.CODE_NOT_REACHABLE,
        analysis_response=AnalysisAnalysisResponse.CAN_NOT_FIX,
        analysis_details="Happy fixing"
    )
    adapter = models.AnalysisAdapter(analysis, finding_stub)

    assert adapter.state == analysis.analysis_state.EXPLOITABLE.value
    assert adapter.justification == analysis.analysis_justification.CODE_NOT_REACHABLE.value
    assert adapter.response == analysis.analysis_response.CAN_NOT_FIX.value
    assert adapter.details == analysis.analysis_details
