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
MAX_EVALUATION_STEPS = 3

class ida_flow_tracer(Workflow):
    # def create_agents(self, mcp_tools):
    flow_tracer: Agent = Agent(
                model=OpenAIChat(id="gpt-4.1-mini"),
                description = flow_tracer.description,
                instructions = flow_tracer.instructions,
                show_tool_calls=True,
                add_history_to_messages=True,
                num_history_responses=5,
                # retries=3,
                memory=AgentMemory(
                    db=SqliteMemoryDb(
                        table_name="tracer_memory",
                        db_file="tracer.db",
                    ),
                ),
                debug_mode=True,
                markdown=True,
            )

    async def initialize(self, session):
        await self.init_tools(self.flow_tracer, session)

    async def init_tools(self, agent, session):
        if not hasattr(self, "mcp_tools"):
            self.mcp_tools = MCPTools(session=session)
            await self.mcp_tools.initialize()

        if  not agent.tools:
            agent.tools = [self.mcp_tools]
        else:
            agent.tools.append(self.mcp_tools)
        
    async def execute_next_steps(self, agent, max_iterations = 1):
        step = 0
        done = False

        prompt = flow_tracer.execute_next_step

        while not done and step < max_iterations:
            print(f"\n🔁 Iteration {step + 1} of {max_iterations}")

            response = await agent.aprint_response(prompt)
            response = agent.get_run_messages().messages[-1]

            if "analysis complete" in response.content.lower():
                done = True
                break

            # (Optional) extract next steps from the content
            # e.g., using regex or your own helper function
            # next_steps = extract_steps(result.content)

            # Simulate execution or real tool usage
            step += 1

        if not done:
            print("⏹️ Max iterations reached. Halting exploration.")


    async def run_trace(
    self,
    address: Optional[str] = None,
    prompt: str = ""
) -> RunResponse:
        # result = await self.flow_tracer.arun(prompt)
        result = await self.flow_tracer.aprint_response(prompt)
        # execute_next_steps = await self.execute_next_steps(self.flow_tracer, MAX_EXECUTION_STEPS)
        return result

    async def trace_function(self, address):
        res = await self.run_trace(prompt=f"Find all the paths/sinks that lead this function: {address}")
        return res
    
async def run_flow_tracer_workflow(address: str) -> RunResponse:
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "python", "-m", "titinsky.mcp.server"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            workflow = ida_flow_tracer()
            await workflow.initialize(session)
            prompt = "Does any attack-controlled packet ever reach strcpy? Generate techniques to find packet handling" \
                        "While analyzing maintain a table of the flow from src to sink."
            prompt = "Find packet handling and find if attacker-controlled buffer of packet can reach strcpy"
            result = await workflow.run_trace(prompt=prompt)
            # result = await workflow.trace_function(address)
            # session.close()