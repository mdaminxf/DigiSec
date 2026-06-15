from plugins.memory.processes import get_processes


def test_processes():

    result = get_processes("memory.raw")

    assert result.success
