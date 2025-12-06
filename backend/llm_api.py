from fastapi import APIRouter
from pydantic import BaseModel
from fastapi import HTTPException
from backend.agents import answer_question_pipeline, agent1_debug_raw
from backend.llm_client import call_llm  

router = APIRouter()


class AskBody(BaseModel):
    question: str


@router.post("/ask")
def ask_llm(body: AskBody):
    try:
        return answer_question_pipeline(body.question)
    except Exception as e:
        # You can log e here if you want
        raise HTTPException(status_code=500, detail=str(e))
    
class Agent1DebugBody(BaseModel):
    question: str


@router.post("/agent1-debug")
def agent1_debug(body: Agent1DebugBody):
    """
    Call Agent 1 (decomposer) and return its RAW LLM output.
    This bypasses JSON parsing so we can see exactly what the model returns.
    """
    try:
        raw = agent1_debug_raw(body.question)
        return {"raw_agent1_output": raw}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

