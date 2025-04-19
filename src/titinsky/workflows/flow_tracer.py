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
MAX_EXECUTION_STEPS = 2
MAX_EVALUATION_STEPS = 1

class ida_flow_tracer(Workflow):
    # def create_agents(self, mcp_tools):
    flow_tracer: Agent = Agent(
                model=OpenAIChat(id="gpt-4.1-mini"),
                description = flow_tracer.description,
                instructions = flow_tracer.instructions,
                # expected_output=address_explorer.expected_output,
                # reasoning=True,
                # tools=[mcp_tools],
                # exponential_backoff=True,
                # add_transfer_instructions=True,
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


    async def evaluate_trace(self, agent, max_iterations=MAX_EVALUATION_STEPS):
        """
        Evaluate the trace results and iterate until the task is complete.
        """
        step = 0
        done = False
        
        while not done and step < max_iterations:
            print(f"\n📊 Evaluation iteration {step + 1} of {max_iterations}")
            
            # Ask the agent to evaluate its findings and identify any gaps
            eval_prompt = "Evaluate your current findings. Have you identified all possible paths? Are there any gaps in your analysis? What additional information would help complete the trace?"
            response = await agent.aprint_response(eval_prompt)
            
            # Check if the evaluation indicates completion
            response_content = agent.get_run_messages().messages[-1].content.lower()
            if "analysis complete" in response_content or "trace complete" in response_content:
                print("✅ Trace evaluation complete")
                done = True
                break
                
            # If not complete, continue with additional exploration
            if not done and step < max_iterations - 1:
                await self.execute_next_steps(agent, 1)
                
            step += 1
            
        if not done:
            print("⏹️ Max evaluation iterations reached. Finalizing trace.")
            
        # Final summary
        await agent.aprint_response("Provide a final summary of all paths/sinks you've identified.")
        
    async def run_trace(
    self,
    address: Optional[str] = None,
    prompt: str = ""
) -> RunResponse:
        # result = await self.flow_tracer.arun(prompt)
        result = await self.flow_tracer.aprint_response(prompt)
        execute_next_steps = await self.execute_next_steps(self.flow_tracer, MAX_EXECUTION_STEPS)
        await self.evaluate_trace(self.flow_tracer)
        return result

    async def trace_function(self, address):
        res = await self.run_trace(prompt=f"Find all the paths/sinks that lead this function: {address}")
        return res


