PLUGIN_MAP = {

    "windows": {
        "processes": "windows.pslist",
        "hidden_processes": "windows.psscan",
        "network": "windows.netscan",
        "cmdline": "windows.cmdline",
        "dlls": "windows.dlllist",
        "malfind": "windows.malfind",
    },

    "linux": {
        "processes": "linux.pslist",
        "hidden_processes": "linux.psscan",
        "network": "linux.sockstat",
        "cmdline": "linux.psaux",
        "malfind": "linux.malfind",
    },

    "mac": {
        "processes": "mac.pslist",
        "network": "mac.netstat",
        "malfind": "mac.malfind",
    }
}
