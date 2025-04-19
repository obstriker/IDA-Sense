from agno.workflow import RunEvent, RunResponse, Workflow
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.tools.mcp import MCPTools
from agno.tools.python import PythonTools
from agno.memory.db.sqlite import SqliteMemoryDb
from agno.agent import AgentMemory
from textwrap import dedent
from typing import Dict, Iterator, List, Optional, Set, Tuple, Union
from enum import Enum
import json
from titinsky.prompts import flow_tracer
from mcp.client.stdio import stdio_client
from mcp import ClientSession, StdioServerParameters
import asyncio
from agno.models.anthropic import Claude

MAX_RETRIES = 1
MAX_EXECUTION_STEPS = 2
MAX_EVALUATION_STEPS = 1

# Add a TraceType enum to categorize different trace operations
class TraceType(Enum):
    SOURCE_TO_SINK = "source_to_sink"
    CALL_PATHS = "call_paths"
    TAINT_ANALYSIS = "taint_analysis"
    FORWARD_REACHABILITY = "forward_reachability"
    VARIABLE_LIFETIME = "variable_lifetime"
    VTABLE_TRACE = "vtable_trace"
    STRUCT_FIELD_USAGE = "struct_field_usage"

class ida_flow_tracer(Workflow):
    # def create_agents(self, mcp_tools):
    def prepare_trace_context(self, trace_type: TraceType, source_addr: str, sink_addr: Optional[str] = None, 
                             variable_name: Optional[str] = None, struct_name: Optional[str] = None):
        """
        Prepare context for different types of flow tracing operations.
        
        Args:
            trace_type: The type of trace to perform
            source_addr: The starting address for the trace
            sink_addr: The target address for source-to-sink traces
            variable_name: Variable name for taint analysis or lifetime tracking
            struct_name: Struct name for field usage tracing
        
        Returns:
            str: Formatted context for the flow tracer agent
        """
        context = f"# Flow Tracing Operation\n\n"
        context += f"## Trace Type: {trace_type.value}\n\n"
        
        if trace_type == TraceType.SOURCE_TO_SINK:
            context += f"- Source Address: {source_addr}\n"
            context += f"- Sink Address: {sink_addr}\n"
            context += f"- Task: Determine if there's a path from source to sink and analyze data flow between them.\n"
        
        elif trace_type == TraceType.CALL_PATHS:
            context += f"- Target Function: {source_addr}\n"
            context += f"- Task: Identify all call paths leading to this function.\n"
        
        elif trace_type == TraceType.TAINT_ANALYSIS:
            context += f"- Starting Function: {source_addr}\n"
            context += f"- Variable to Track: {variable_name}\n"
            context += f"- Task: Track all changes to this variable and any aliases in callees.\n"
        
        elif trace_type == TraceType.FORWARD_REACHABILITY:
            context += f"- Starting Point: {source_addr}\n"
            context += f"- Task: Identify all functions that can be reached directly or indirectly from this point.\n"
        
        elif trace_type == TraceType.VARIABLE_LIFETIME:
            context += f"- Function Address: {source_addr}\n"
            context += f"- Variable: {variable_name}\n"
            context += f"- Task: Trace the lifetime of this variable from entry to exit.\n"
        
        elif trace_type == TraceType.VTABLE_TRACE:
            context += f"- VTable Address/Reference: {source_addr}\n"
            context += f"- Task: Trace vtable or function pointer table to identify potential dynamic call targets.\n"
        
        elif trace_type == TraceType.STRUCT_FIELD_USAGE:
            context += f"- Struct Name: {struct_name}\n"
            context += f"- Task: Trace how fields in this struct are used throughout the program.\n"
        
        return context
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


    async def run_trace(
        self,
        address: Optional[str] = None,
        prompt: str = "",
        collect_results: bool = True
    ) -> RunResponse:
        """
        Run a flow tracing operation with the given prompt.
        
        Args:
            address: Optional address to focus the trace on
            prompt: The specific tracing prompt
            collect_results: Whether to collect and structure the results
            
        Returns:
            RunResponse: The agent's response
        """
        # Add address to the prompt if provided but not already in the prompt
        if address and address not in prompt:
            prompt = f"Focus on address {address}.\n\n{prompt}"
        
        # Run the initial analysis
        result = await self.flow_tracer.aprint_response(prompt)
        
        # Execute follow-up steps
        await self.execute_next_steps(self.flow_tracer, MAX_EXECUTION_STEPS)
        
        # If we want to collect structured results, we could parse the agent's response
        if collect_results:
            # This would be implemented based on the expected output format
            # For now, we just return the raw result
            pass
        
        return result

    async def trace_function(self, address):
        res = await self.run_trace(prompt=f"Find all the paths/sinks that lead this function: {address}")
        return res
        
    async def trace_source_to_sink(self, source_addr: str, sink_addr: str) -> RunResponse:
        """Trace if data flows from source to sink address."""
        context = self.prepare_trace_context(
            TraceType.SOURCE_TO_SINK, 
            source_addr=source_addr, 
            sink_addr=sink_addr
        )
        prompt = f"{context}\n\nDetermine if there is a data flow path from the source function at {source_addr} to the sink function at {sink_addr}. If so, describe the complete path and any data transformations along the way."
        return await self.run_trace(prompt=prompt)

    async def trace_call_paths(self, target_addr: str) -> RunResponse:
        """Find all call paths leading to a specific function."""
        context = self.prepare_trace_context(
            TraceType.CALL_PATHS,
            source_addr=target_addr
        )
        prompt = f"{context}\n\nIdentify and map all possible call paths that lead to the function at {target_addr}. Show the complete call hierarchy."
        return await self.run_trace(prompt=prompt)

    async def trace_taint_analysis(self, function_addr: str, variable_name: str) -> RunResponse:
        """Track a variable and its aliases through a function and its callees."""
        context = self.prepare_trace_context(
            TraceType.TAINT_ANALYSIS,
            source_addr=function_addr,
            variable_name=variable_name
        )
        prompt = f"{context}\n\nPerform taint analysis on the variable '{variable_name}' in function at {function_addr}. Track all changes to this variable and any aliases in callees. Identify if this variable could be attacker-controlled."
        return await self.run_trace(prompt=prompt)

    async def trace_forward_reachability(self, start_addr: str) -> RunResponse:
        """Identify all functions reachable from a starting point."""
        context = self.prepare_trace_context(
            TraceType.FORWARD_REACHABILITY,
            source_addr=start_addr
        )
        prompt = f"{context}\n\nPerform forward reachability analysis starting from {start_addr}. Identify all functions that can be reached directly or indirectly from this point."
        return await self.run_trace(prompt=prompt)

    async def trace_variable_lifetime(self, function_addr: str, variable_name: str) -> RunResponse:
        """Trace the lifetime of a variable from entry to exit."""
        context = self.prepare_trace_context(
            TraceType.VARIABLE_LIFETIME,
            source_addr=function_addr,
            variable_name=variable_name
        )
        prompt = f"{context}\n\nTrace the complete lifetime of variable '{variable_name}' in the function at {function_addr}, from entry to exit. Show all operations performed on it and how its value changes."
        return await self.run_trace(prompt=prompt)

    async def trace_vtable(self, vtable_addr: str) -> RunResponse:
        """Trace vtable or function pointer table to see where dynamic calls may go."""
        context = self.prepare_trace_context(
            TraceType.VTABLE_TRACE,
            source_addr=vtable_addr
        )
        prompt = f"{context}\n\nAnalyze the vtable or function pointer table at {vtable_addr}. Identify all possible dynamic call targets and where they might be used."
        return await self.run_trace(prompt=prompt)

    async def trace_struct_field_usage(self, struct_name: str) -> RunResponse:
        """Trace how fields in a struct are used throughout the program."""
        context = self.prepare_trace_context(
            TraceType.STRUCT_FIELD_USAGE,
            struct_name=struct_name
        )
        prompt = f"{context}\n\nTrace how fields in the struct '{struct_name}' are used throughout the program. Identify access patterns and potential data flows."
        return await self.run_trace(prompt=prompt)
