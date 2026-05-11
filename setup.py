import os
import re
import subprocess
from shutil import copyfile

# Define paths and filenames
home_dir = os.path.expanduser("~")
local_bin_dir = os.path.join(home_dir, ".local", "bin")
nxcscan_script = "nxcscan.py"

# Build extended PATH environment so pipx and nxc can be found
# even if the script is run from a context where .zshrc hasn't been sourced
env = os.environ.copy()
extra_paths = [
    os.path.join(home_dir, ".local", "bin"),
    "/usr/local/bin",
]
env["PATH"] = ":".join(extra_paths) + ":" + env.get("PATH", "")

# Create the .local/bin directory if it doesn't exist
if not os.path.exists(local_bin_dir):
    os.makedirs(local_bin_dir)

# Copy the script to .local/bin
nxcscan_dest = os.path.join(local_bin_dir, "nxcscan.py")
copyfile(nxcscan_script, nxcscan_dest)
os.chmod(nxcscan_dest, 0o755)

# Check nxc version and force install if below 1.30
def get_nxc_version(env=None):
    try:
        result = subprocess.run(
            ["nxc", "--version"], capture_output=True, text=True, timeout=10, env=env
        )
        version_str = result.stdout.strip() or result.stderr.strip()
        match = re.search(r'(\d+)\.(\d+)', version_str)
        if match:
            return int(match.group(1)), int(match.group(2))
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass
    return None

def install_nxc(env):
    print("Installing/updating nxc via pipx...")

    # Find pipx explicitly so we get a clear error if it's still missing
    pipx_path = subprocess.run(
        ["which", "pipx"], capture_output=True, text=True, env=env
    ).stdout.strip()

    if not pipx_path:
        raise FileNotFoundError(
            "pipx not found. Install it with: sudo apt install pipx  OR  python3 -m pip install --user pipx"
        )

    subprocess.run(
        [pipx_path, "install", "git+https://github.com/Pennyw0rth/NetExec", "--force"],
        check=True,
        env=env
    )
    print("nxc installation complete.")

version = get_nxc_version(env=env)
if version is None:
    print("nxc not found. Installing...")
    install_nxc(env)
elif version < (1, 30):
    print(f"nxc version {version[0]}.{version[1]} is below 1.30. Upgrading...")
    install_nxc(env)
else:
    print(f"nxc version {version[0]}.{version[1]} satisfies the requirement (>= 1.30). Skipping install.")

# Determine the shell and set the alias
shell = os.environ.get("SHELL", "").lower()
alias_command = f'\nalias nxcscan="python3 {nxcscan_dest}"\n'

# Source the correct shell configuration file
config_file = None
if "zsh" in shell:
    config_file = os.path.join(home_dir, ".zshrc")
elif "bash" in shell:
    config_file = os.path.join(home_dir, ".bashrc")

if config_file:
    with open(config_file, "a") as shell_rc:
        shell_rc.write(alias_command)
    print(f"Alias added to {config_file}.")
    print(f"To use the alias immediately, run:\n  source {config_file}")
else:
    print("Unknown shell. Please add the following alias manually:")
    print(alias_command)

print(f"nxcscan has been installed to {nxcscan_dest}. You can run it using 'nxcscan' after sourcing your shell configuration.")
