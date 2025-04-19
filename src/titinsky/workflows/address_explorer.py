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
from titinsky.prompts import address_explorer, address_validator, renaming_scorer
from mcp.client.stdio import stdio_client
from mcp import ClientSession, StdioServerParameters
import asyncio
from agno.models.anthropic import Claude

MAX_RETRIES = 1
MAX_EXECUTION_STEPS = 1
MAX_EVALUATION_STEPS = 1

class ida_reflective_explorer(Workflow):
    # def create_agents(self, mcp_tools):
    explorer: Agent = Agent(
                model=OpenAIChat(id="gpt-4.1-mini"),
                # model=Claude(id="claude-3-7-sonnet-20250219"),
                description=address_explorer.description,
                instructions=address_explorer.instructions,
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

    validator: Agent = Agent(
                model=OpenAIChat(id="gpt-4.1-mini"),
                # model=Claude(id="claude-3-7-sonnet-20250219"),
                description=address_validator.description,
                instructions=address_validator.instructions,
                show_tool_calls=True,
                add_history_to_messages=True,
                num_history_responses=3,
                memory=AgentMemory(
                    db=SqliteMemoryDb(
                        table_name="agent_memory",
                        db_file="tmp.db",
                    ),
                ),
                debug_mode=True,
                markdown=True,
            )

    name_scorer: Agent = Agent(
            model=OpenAIChat(id="gpt-4o-mini"),
            description=renaming_scorer.description,
            instructions=renaming_scorer.instructions,
            show_tool_calls=True,
            add_history_to_messages=True,
            memory=AgentMemory(
                db=SqliteMemoryDb(table_name="agent_memory", db_file="tmp.db"),
            ),
            debug_mode=True,
            markdown=True,
        )

    async def initialize(self, session):
        await self.init_tools(self.explorer, session)
        await self.init_tools(self.validator, session)

    async def init_tools(self, agent, session):
        if not hasattr(self, "mcp_tools"):
            self.mcp_tools = MCPTools(session=session)
            await self.mcp_tools.initialize()

        if  not agent.tools:
            agent.tools = [self.mcp_tools]
        else:
            agent.tools.append(self.mcp_tools)
        
    # WIP
    def prepare_context(self, address, xref = False, memory = False, call_graph = False):
        if not address:
            return

        if xref:
            xrefs = self.mcp_tools.get_xrefs_to(address)
        
        if memory:
            memory_data = self.mcp_tools.get_bytes_from(address)

        if call_graph:
            call_graph = self.mcp_tools.get_call_graph(address)

        return {"xrefs": xrefs, "memory" : memory_data, "call_graph" : call_graph}


    async def run_explore(
    self,
    address: Optional[str] = None,
) -> RunResponse:
        res = False

        await self.explorer.arun(f"Explore the memory address {address} and suggest a meaningful name.")
        # await self.execute_next_steps(self.explorer, MAX_EXECUTION_STEPS)
        res = await self.evaluate(self.validator, self.explorer, address, MAX_EVALUATION_STEPS)
        # t = self.prepare_context(address, xref=True, memory=True, call_graph=True)
        # Remove and add to validator to save tokens
        await self.explorer.arun(f"rename {address}")

        if not res:
            print("Failed validation.")
            return False
        else:
            print("✅ Passed validation.")
            return True

        ## Give naming score
        # scorer_prompt = address_scorer.prompt_template.format(
            # address=address,
            # name=suggested_name,
            # analysis=exploration_output.content
        # )


    async def execute_next_steps(self, agent, max_iterations = 1):
        step = 0
        done = False

        prompt = address_explorer.execute_next_step

        while not done and step < max_iterations:
            print(f"\n🔁 Iteration {step + 1} of {max_iterations}")

            response = await agent.arun(prompt)
            print(response.content)

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

    # ask the agent if he accomplished the result
    # Change to scorer and above grade X the agent passes
    async def evaluate(self, validator, validated, address, evaluation_steps = 1):
        attempt = 0
        validated_last_message = validated.get_run_messages().messages[-1]

        while attempt < evaluation_steps:
            validator_prompt = f"""{address_validator.prompt}
                --- BEGIN AGENT OUTPUT ---
                {validated_last_message.content}
                --- END AGENT OUTPUT ---
                """
            validation_output = await validator.arun(validator_prompt)
            
            if "FAIL" in validation_output.content:
                print("❌ Validation failed. Rerunning exploration with feedback...")
                validated_last_message = await validated.aprint_response(
                    f"The validation failed with the following feedback:\n{validation_output.content}\n\n"
                    f"Please improve your analysis of address {address} accordingly."
                )
                res = False
            else:
                res = True
            attempt += 1

        return res

async def run_address_workflow(address: str) -> RunResponse:
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "python", "-m", "titinsky.mcp.server"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            workflow = ida_reflective_explorer()
            await workflow.initialize(session)
            result = await workflow.run_explore(address)
            session.close()