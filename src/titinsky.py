from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.tools.python import PythonTools
from idatools import *
from prompts import default_prompt_zh

# Initialize Agno AI agent
agent = Agent(
    model=OpenAIChat(id="gpt-4o"),
    tools=[IdaTools(), PythonTools(run_code=True)],
    description=default_prompt_zh,
    show_tool_calls=True,
    debug_mode=True,
    markdown=True
)

## TODO: Add correction agent that suggests strategies? (Self-correcting and self-reflective prompting)
## IDEA: Add ranker/evaluator/validator to ensure correct renaming