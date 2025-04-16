# workflows/ida_reflective_explorer.py

from agno.workflow import RunEvent, RunResponse, Workflow
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.tools.mcp import MCPTools
from agno.tools.python import PythonTools
from agno.memory.db.sqlite import SqliteMemoryDb
from agno.agent import AgentMemory
from textwrap import dedent
from typing import Dict, Iterator, Optional
from titinsky.prompts import flow_tracer
from mcp.client.stdio import stdio_client
from mcp import ClientSession, StdioServerParameters
import asyncio
from agno.models.anthropic import Claude

MAX_RETRIES = 1
MAX_EXECUTION_STEPS = 1
MAX_EVALUATION_STEPS = 1

class ida_flow_tracer(Workflow):
    # def create_agents(self, mcp_tools):
    flow_tracer: Agent = Agent(
                model=OpenAIChat(id="gpt-4o-mini"),
                description = flow_tracer.description,
                instructions = flow_tracer.instructions,
                # expected_output=address_explorer.expected_output,
                # reasoning=True,
                # tools=[mcp_tools],
                exponential_backoff=True,
                add_transfer_instructions=True,
                show_tool_calls=True,
                add_history_to_messages=True,
                num_history_responses=5,
                # retries=3,
                memory=AgentMemory(
                    db=SqliteMemoryDb(
                        table_name="agent_memory",
                        db_file="tmp.db",
                    ),
                ),
                debug_mode=True,
                markdown=True,
            )

    async def initialize(self, session):
        await self.init_tools(self.explorer, session)

    async def init_tools(self, agent, session):
        if not hasattr(self, "mcp_tools"):
            self.mcp_tools = MCPTools(session=session)
            await self.mcp_tools.initialize()

        if  not agent.tools:
            agent.tools = [self.mcp_tools]
        else:
            agent.tools.append(self.mcp_tools)
        
    async def run_trace(
    self,
    address: Optional[str] = None,
    session: Optional[ClientSession] = None,
) -> RunResponse:
        pass

async def run_address_workflow(address: str) -> RunResponse:
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "python", "-m", "titinsky.mcp.server"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            workflow = ida_flow_tracer()
            await workflow.initialize(session)
            result = await workflow.run_trace(address)
            session.close()