TOOLS = []


def register_tool(func):
    TOOLS.append(func)
    return func


def get_tools():
    return TOOLS
