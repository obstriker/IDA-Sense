from agno.agent import Agent
from agno.models.openai import OpenAIChat
from idatools import *
from prompts import default_prompt_zh

# Initialize Agno AI agent
agent = Agent(
    model=OpenAIChat(id="gpt-4o"),
    tools=[IdaTools()],
    description=default_prompt_zh,
    show_tool_calls=True,
    debug_mode=True,
    markdown=True
)