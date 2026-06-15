from core.volatility import run_plugin


def detect_os(memory_file: str):

    try:
        run_plugin(
            memory_file,
            "windows.info"
        )
        return "windows"
    except:
        pass

    try:
        run_plugin(
            memory_file,
            "linux.banner"
        )
        return "linux"
    except:
        pass

    try:
        run_plugin(
            memory_file,
            "mac.banner"
        )
        return "mac"
    except:
        pass

    return "unknown"
