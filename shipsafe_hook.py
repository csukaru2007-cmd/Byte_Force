"""PlatformIO pre-build hook: stop the build when ShipSafe finds a CRITICAL dependency problem.

How to use it in an ESP32 project:
  1. Copy this file next to the project's platformio.ini.
  2. Add to the [env:...] section of platformio.ini:

        extra_scripts = pre:shipsafe_hook.py
        custom_shipsafe_dir = C:/path/to/AI_AGENT        ; folder that contains ShipSafe's main.py

  3. Run `pio run` as usual. CRITICAL -> the build stops. MEDIUM -> a warning, the build goes on.

Note: depending on the PlatformIO version, lib_deps may already have been downloaded
before pre: scripts run. The hook then stops the firmware from being built and uploaded.
To make sure nothing is ever downloaded, run main.py yourself before the first `pio run`.
"""

import os
import subprocess

Import("env")  # noqa: F821  - provided by PlatformIO (SCons) when it runs this script

project_dir = env.subst("$PROJECT_DIR")  # noqa: F821
shipsafe_dir = env.GetProjectOption("custom_shipsafe_dir", "")  # noqa: F821

if not shipsafe_dir or not os.path.isfile(os.path.join(shipsafe_dir, "main.py")):
    print("ShipSafe: set custom_shipsafe_dir in platformio.ini to the folder containing main.py")
    env.Exit(1)  # noqa: F821  - fail closed: a missing security check must not look like a pass

# Exit codes from main.py: 0 = GOOD, 2 = MEDIUM, 1 = CRITICAL, anything else = the check failed
result = subprocess.run(
    ["uv", "run", "--project", shipsafe_dir, "python", os.path.join(shipsafe_dir, "main.py"), project_dir, "--quiet"],
)
if result.returncode == 0:
    print("ShipSafe: dependencies look GOOD.")
elif result.returncode == 2:
    print("ShipSafe: MEDIUM findings - building anyway. Read report.json and fix them.")
else:
    print("ShipSafe: CRITICAL dependency problem (or the check failed) - build stopped. See report.json")
    env.Exit(1)  # noqa: F821
