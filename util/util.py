#
# Util module
#

import os
import platform

WIN_LOG_SOURCE_EXEC = r"c:\Program Files (x86)\AlertLogic\agent\al-elc.exe.current"
LINUX_LOG_SOURCE_EXEC = "/var/alertlogic/lib/agent/bin/al-slc.current"

WIN_PHOST_EXEC = r"c:\Program Files (x86)\AlertLogic\agent\al-tmhost.exe.current"
LINUX_PHOST_EXEC = "/var/alertlogic/lib/agent/bin/al-tmhost.current"

WIN_HOST_EXEC = r"c:\Program Files (x86)\AlertLogic\agent\al-agent.exe"
LINUX_HOST_EXEC = "/var/alertlogic/lib/agent/bin/al-agent"


def is_windows():
    if platform.system().lower() == "windows":
        return True
    else:
        return False


def is_linux():
    if platform.system().lower() == "linux":
        return True
    else:
        return False


def does_source_exec_exists():
    if is_windows():
        return os.path.exists(WIN_LOG_SOURCE_EXEC)
    elif is_linux():
        return os.path.exists(LINUX_LOG_SOURCE_EXEC)
    else:
        return False


def does_phost_exec_exists():    
    if is_windows():
        return os.path.exists(WIN_PHOST_EXEC)
    elif is_linux():
        return os.path.exists(LINUX_PHOST_EXEC)
    else:
        return False


def does_host_exec_exists():
    if is_windows():
        return os.path.exists(WIN_HOST_EXEC)
    elif is_linux():
        return os.path.exists(LINUX_HOST_EXEC)
    else:
        return False    