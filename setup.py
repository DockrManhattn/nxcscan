import os
from shutil import copyfile

# Define paths and filenames
home_dir = os.path.expanduser("~")
local_bin_dir = os.path.join(home_dir, ".local", "bin")
nxcscan_script = "nxcscan.py"

# Create the .local/bin directory if it doesn't exist
if not os.path.exists(local_bin_dir):
    os.makedirs(local_bin_dir)

# Copy the script to .local/bin
nxcscan_dest = os.path.join(local_bin_dir, "nxcscan.py")
copyfile(nxcscan_script, nxcscan_dest)
os.chmod(nxcscan_dest, 0o755)

# Determine the shell and set the alias
shell = os.environ.get("SHELL", "").lower()
alias_command = f'alias nxcscan="python3 {nxcscan_dest}"\n'

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
