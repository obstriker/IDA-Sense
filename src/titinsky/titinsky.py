from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.tools.python import PythonTools
from titinsky.prompts import *
from agno.tools.mcp import MCPTools
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from agno.models.anthropic import Claude
import asyncio
from dotenv import load_dotenv
from agno.memory.db.sqlite import SqliteMemoryDb
from agno.agent import Agent, AgentMemory

load_dotenv()

# TODO: Fix installation of plugin, make it easy and modular (maybe python -m titinsky --install)

async def create_ida_agent(session):
    mcp_tools = MCPTools(session=session)
    await mcp_tools.initialize()
    return Agent(
        model=OpenAIChat(id="gpt-4o-mini"),
        # model=Claude(id="claude-3-7-sonnet-20250219"),
        description=address_explorer.description,
        instructions=address_explorer.instructions,
        tools=[mcp_tools, PythonTools(run_code=True)],
        # show_tool_calls=True,
        # reasoning=True,
        # debug_mode=True,
        markdown=True
    )

async def run_agent(message: str, reasoning=False) -> None:
    """Run the filesystem agent with the given message."""
    # Initialize the MCP server
    server_params = StdioServerParameters(
    command="uv",
    args=[
        "run",
        "python",
        "-m",
        "titinsky.mcp.server",
    ],
    )
    # Create a client session to connect to the MCP server
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            agent = await create_ida_agent(session)

            # Run the agent
            await agent.aprint_response(message, stream=True)
            # await agent.cli_app()

async def test_address_explore(address, reasoning=False):
    # asyncio.run(run_agent(f"Explore the following address {address}", reasoning=reasoning))
    from titinsky.workflows.address_explorer import run_address_workflow
    await run_address_workflow(address)

def test_function_explore(address, reasoning=False):
    asyncio.run(run_agent(f"Explore the following function {address}", reasoning=reasoning))

def test_trace_function(address, reasoning=False):
    asyncio.run(run_agent(f"Trace the following function {address}", reasoning=reasoning))

def test_trace_address(address, reasoning=False):
    asyncio.run(run_agent(f"Trace the following data address {address}", reasoning=reasoning))


import argparse

def main():
    parser = argparse.ArgumentParser(description="Titinsky Command Line Interface")
    parser.add_argument("--explore_address", type=str, help="Address to explore")
    parser.add_argument("--explore_function", type=str, help="Function address to explore")
    parser.add_argument("--trace_address", type=str, help="Trace data address")
    parser.add_argument("--trace_func", type=str, help="Trace function")
    parser.add_argument("--query", type=str, help="Query about the program")
    parser.add_argument("--reasoning", action="store_true", help="Reasoning for the agent")

    args = parser.parse_args()

    if args.explore_address:
        asyncio.run(test_address_explore(args.explore_address, reasoning=args.reasoning))
    elif args.explore_function:
        test_function_explore(args.explore_function,reasoning=args.reasoning)
    elif args.trace_address:
        test_trace_address(args.trace_address,reasoning=args.reasoning)
    elif args.trace_func:
        test_trace_function(args.trace_func,reasoning=args.reasoning)
    elif args.query:
        asyncio.run(run_agent(args.query, reasoning=args.reasoning))
    else:
        print("No valid arguments provided. Use --help for more information.")

if __name__ == "__main__":
    main()

# Install ida plugin and mcp server
# python -m titinsky.mcp.server --install
# Run:
# python -m titinsky.titinsky

## TODO: Add correction agent that suggests strategies? (Self-correcting and self-reflective prompting)
## IDEA: Add ranker/evaluator/validator to ensure correct renaming