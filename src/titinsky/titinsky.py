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

async def run_agent(message: str) -> None:
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

def test_address_explore(address):
    asyncio.run(run_agent(f"Explore the following address {address}"))

def main():
    test_address_explore("0x415878")

if __name__ == "__main__":
    main()

# Install ida plugin and mcp server
# python -m titinsky.mcp.server --install
# Run:
# python -m titinsky.titinsky

## TODO: Add correction agent that suggests strategies? (Self-correcting and self-reflective prompting)
## IDEA: Add ranker/evaluator/validator to ensure correct renaming