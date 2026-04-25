#!/usr/bin/env python3
"""
Script Name: template_script.py
Description: Python script template using ~/.config/<APPLICATION_NAME>/config.json for configuration.
Author: dockrmanhattn@gmail.com
Date: 2026-04-25
"""

import os
import sys
import json
import logging
import argparse
import re
import subprocess
import shlex
from datetime import datetime
from logging.handlers import RotatingFileHandler
from colorama import init, Fore

init(autoreset=True)  # Initialize colorama

# Config and defaults
APPLICATION_NAME = os.path.splitext(os.path.basename(sys.argv[0]))[0]  # Derived from filename
CONFIG_FILENAME = "config.json"      # Config file name
LOG_LEVEL_DEFAULT = "INFO"           # Default console log level
CONFIG_DIR = os.path.expanduser(f"~/.config/{APPLICATION_NAME}")
CONFIG_PATH = os.path.join(CONFIG_DIR, CONFIG_FILENAME)

DEFAULT_CONFIG = {
    "LOG_LEVEL": LOG_LEVEL_DEFAULT,
    "MAX_BYTES": 500_000,            # Approx size for ~1000 lines
    "BACKUP_COUNT": 5,               # Number of rotated logs to keep
    "CURRENT_DIR": os.getcwd(),
    "OUTPUT_DIR": os.path.join(os.getcwd(), APPLICATION_NAME)  # Default; overridden by -o/-outputdir
}

SERVICE_PORTS = {
    "ftp": "21",
    "ldap": "389",
    "mssql": "1433",
    # "rdp": "3389",  # RDP scan removed due to time consumption
    "smb": "445",
    "ssh": "22",
    "vnc": "5900",
    "winrm": "5985,5986",
    "wmi": "135",
}

DEFAULT_SERVICES = ["ftp", "ldap", "mssql", "smb", "ssh", "vnc", "winrm", "wmi"]


def normalize_target(target):
    if "/" not in target:
        return f"{target}/32"
    return target


def convert_target_to_filename(target, username='', domain=''):
    filename = target.replace('/', '-')
    if username:
        filename += f'-{username}'
    if domain:
        filename += f'-{domain.replace(".", "-")}'
    return filename


def highlight_pwned_lines(file_content, username, domain):
    lines = file_content.split('\n')
    highlighted_lines = []

    for line in lines:
        if username and "(Pwn3d!)" in line and username in line:
            # Style (Pwn3d!) as bright purple bold
            styled_line = line.replace("(Pwn3d!)", "\033[1;95m(Pwn3d!)\033[0m")
            highlighted_lines.append(f"{Fore.LIGHTMAGENTA_EX}{styled_line}{Fore.RESET}")
        else:
            highlighted_lines.append(line)

    return '\n'.join(highlighted_lines)


def colorize_nxc_output(output, base_color=None):
    """Colorize IP addresses, ports, and hostnames in nxc output for better readability."""
    import re
    
    lines = output.split('\n')
    colorized_lines = []
    
    for line in lines:
        # Skip empty lines
        if not line.strip():
            colorized_lines.append(line)
            continue
        
        # Use regex to find and colorize IP, port, and hostname while preserving spacing
        # Pattern: protocol + spaces + IP + spaces + port + spaces + hostname + rest
        # This preserves the original nxc formatting
        pattern = r'^(\w+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,5})\s+([^\s]+)(.*)$'
        match = re.match(pattern, line)
        
        if match:
            protocol, ip, port, hostname, rest = match.groups()
            colorized_line = f"{protocol} {Fore.GREEN}{ip}{Fore.RESET} {Fore.YELLOW}{port}{Fore.RESET} {Fore.CYAN}{hostname}{Fore.RESET}{rest}"
        else:
            # If line doesn't match expected format, leave as-is
            colorized_line = line
        
        # Highlight READ,WRITE permissions in bright cyan
        if "READ,WRITE" in colorized_line:
            colorized_line = colorized_line.replace("READ,WRITE", "\033[1;96mREAD,WRITE\033[0m")
        
        if base_color:
            colorized_line = f"{base_color}{colorized_line}{Fore.RESET}"
        
        # Style (Pwn3d!) as bright purple bold
        colorized_line = colorized_line.replace("(Pwn3d!)", "\033[1;95m(Pwn3d!)\033[0m")
        
        colorized_lines.append(colorized_line)
    
    return '\n'.join(colorized_lines)


def build_nxc_command(protocol, target, username, password, hash_value, ticket, domain, use_proxychains, local_auth, shares=False):
    command = "proxychains -q " if use_proxychains else ""
    command += f"nxc {protocol} {target}"
    if username is not None:
        # For SSH, append domain to username if domain is provided
        if protocol == "ssh" and domain:
            command += f" -u {shlex.quote(f'{username}@{domain}')}"
        else:
            command += f" -u {shlex.quote(username)}"
    if password is not None:
        command += f" -p {shlex.quote(password)}"
    if hash_value:
        command += f" -H {shlex.quote(hash_value)}"
    if ticket:
        command += " --use-kcache"
    if domain and not local_auth and protocol != "ssh":
        command += f" -d {domain}"
    if shares or protocol == "smb":
        command += " --shares"
    if local_auth:
        command += " --local-auth"
    return command


def parse_rustscan_ips(output):
    hosts = set()
    for line in output.splitlines():
        match = re.search(r"Open\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3}):(\d+)", line)
        if match:
            hosts.add(match.group(1))
    return hosts


def run_rustscan_for_ports(target, ports, logger):
    if not ports:
        return set()
    cmd = ["rustscan", "-a", target, "-p", ports, "--ulimit", "1500", "--scripts", "none"]
    logger.debug(f"Running discovery command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        logger.error("rustscan is not installed or not available in PATH.")
        return set()

    if result.returncode != 0:
        logger.warning("rustscan exited with a non-zero status while discovering hosts.")
        logger.debug(result.stderr.strip())

    hosts = parse_rustscan_ips(result.stdout)
    logger.debug(f"Discovered {len(hosts)} host(s) for ports {ports}")
    if hosts:
        logger.info(f"Discovered {len(hosts)} host(s) for ports {ports}")
    return hosts


def run_command_with_tee(command, output_file, logger):
    # Write the initial command header into the output file, then stream execution to both terminal and file.
    with open(output_file, "w", encoding="utf-8") as out:
        out.write(f"\n\n{Fore.BLUE}Command run to generate this output:\n{Fore.RESET}{Fore.LIGHTYELLOW_EX}{command}{Fore.RESET}\n")

    shell_cmd = f"{command} 2>&1 | tee -a {shlex.quote(output_file)}"
    logger.debug(f"Executing command with tee: {shell_cmd}")
    result = subprocess.run(shell_cmd, shell=True, text=True)
    return result


def discover_service_hosts(target, services, logger):
    logger.info(f"Discovering service hosts for {target}")
    service_hosts = {}
    for service in services:
        ports = SERVICE_PORTS.get(service)
        if not ports:
            logger.warning(f"Skipping unknown service: {service}")
            continue
        hosts = run_rustscan_for_ports(target, ports, logger)
        service_hosts[service] = sorted(hosts)
    return service_hosts


def write_service_discovery_files(service_hosts, output_dir, logger):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    discovery_file = os.path.join(output_dir, "service-discovery.txt")
    with open(discovery_file, "w", encoding="utf-8") as f:
        for service, hosts in service_hosts.items():
            f.write(f"{service}:\n")
            for host in hosts:
                f.write(f"  {host}\n")
            f.write("\n")
    logger.debug(f"Wrote discovery results to {discovery_file}")


def run_nxc_on_discovered_hosts(service_hosts, args, output_dir, logger):
    for service, hosts in service_hosts.items():
        if not hosts:
            logger.debug(f"No hosts discovered for {service}, skipping nxc.{service}")
            continue
        for host in hosts:
            variants = []
            if service == "smb":
                variants.append({"username": "", "password": "", "hash_value": "", "ticket": False, "label": "anonymous access"})
                variants.append({"username": "a", "password": "", "hash_value": "", "ticket": False, "label": "guest access"})
                if args.username:
                    if args.password:
                        variants.append({"username": args.username, "password": args.password, "hash_value": "", "ticket": False, "label": f"{args.username}-pass"})
                    if args.hash:
                        variants.append({"username": args.username, "password": "", "hash_value": args.hash, "ticket": False, "label": f"{args.username}-hash"})
                    if args.ticket:
                        variants.append({"username": args.username, "password": "", "hash_value": "", "ticket": True, "label": f"{args.username}-kcache"})
            else:
                if not args.username:
                    variants.append({"username": None, "password": None, "hash_value": None, "ticket": False, "label": "default"})
                else:
                    if args.password:
                        variants.append({"username": args.username, "password": args.password, "hash_value": None, "ticket": False, "label": f"{args.username}-pass"})
                    if args.hash:
                        variants.append({"username": args.username, "password": None, "hash_value": args.hash, "ticket": False, "label": f"{args.username}-hash"})
                    if args.ticket:
                        variants.append({"username": args.username, "password": None, "hash_value": None, "ticket": True, "label": f"{args.username}-kcache"})

            for variant in variants:
                command = build_nxc_command(
                    service,
                    host,
                    variant["username"],
                    variant["password"],
                    variant["hash_value"],
                    variant["ticket"],
                    args.domain,
                    args.proxychains,
                    args.local_auth,
                    shares=(service == "smb"),
                )
                target_filename = convert_target_to_filename(args.target, variant["username"], args.domain)
                output_file = os.path.join(output_dir, f"nxc-{service}-{target_filename}-{host}-{variant['label']}.txt")
                try:
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                except Exception as exc:
                    logger.error(f"Failed to run nxc command for {host}: {exc}")
                    continue

                base_color = None
                if "(Pwn3d!)" in result.stdout:
                    base_color = Fore.LIGHTMAGENTA_EX
                elif result.stdout and "[-]" in result.stdout:
                    base_color = Fore.RED
                elif result.returncode != 0 and "unrecognized arguments" in result.stderr:
                    base_color = Fore.RED

                # Only log running and command for non-failed runs
                if base_color != Fore.RED:
                    logger.info(f"Running nxc {service} against {host} [{variant['label']}]")
                    logger.info(f"Command: {command}")

                # Check for pwned indication
                pwned_line = ""
                if "(Pwn3d!)" in result.stdout and args.username and args.username in result.stdout:
                    pwned_line = f"🎉🎉🎉🎉🎉 \033[1;95mPWNED! {host} {service} with {variant['username']}\033[0m 🎉🎉🎉🎉🎉"

                colorized_output = colorize_nxc_output(result.stdout, base_color) if result.stdout else ""

                # Insert pwned line at the beginning of output
                if pwned_line:
                    colorized_output = pwned_line + '\n' + colorized_output

                # Write output to file
                with open(output_file, "w", encoding="utf-8") as out:
                    out.write(f"\n\n{Fore.BLUE}Command run to generate this output:\n{Fore.RESET}{Fore.LIGHTYELLOW_EX}{command}{Fore.RESET}\n")
                    out.write(colorized_output)
                    if result.stderr:
                        out.write("\nSTDERR:\n")
                        out.write(result.stderr)

                # Display the output in console via logger
                if colorized_output.strip() and base_color != Fore.RED:
                    for line in colorized_output.strip().split('\n'):
                        if line.strip():
                            print(line)
                if result.stderr.strip() and base_color != Fore.RED and "unrecognized arguments" not in result.stderr:
                    logger.warning(f"STDERR for {host}: {result.stderr.strip()}")

                # Highlight pwned lines in the output file
                with open(output_file, 'r', encoding="utf-8") as f:
                    file_content = f.read()

                modified_content = highlight_pwned_lines(file_content, args.username, args.domain)

                with open(output_file, 'w', encoding="utf-8") as f:
                    f.write(modified_content)

                if result.returncode == 0:
                    logger.debug(f"Saved nxc output to {output_file}")
                else:
                    if "unrecognized arguments" in result.stderr:
                        logger.debug(f"nxc exited {result.returncode} for {host}; see {output_file}")
                    else:
                        logger.warning(f"nxc exited {result.returncode} for {host}; see {output_file}")


# Static logging style (not persisted to user config)
LOG_STYLE = {
    "BLUE": "\u001b[94m",
    "YELLOW": "\u001b[93m",
    "RED": "\u001b[91m",
    "RESET": "\u001b[0m",
    "DEBUG_EMOJI": "{🔧🐛[+]🐛🔧}",
    "INFO_EMOJI": "{🌀🌵[+]🌵🌀}",
    "WARNING_EMOJI": "{⚡⚡[+]⚡⚡}",
    "ERROR_EMOJI": "{🔥💀[+]💀🔥}",
    "CRITICAL_EMOJI": "{🚨🔥[+]🔥🚨}",
    "DEBUG_PREFIX": "{BLUE}{DEBUG_EMOJI}{RESET}",
    "INFO_PREFIX": "{YELLOW}{INFO_EMOJI}{RESET}",
    "WARNING_PREFIX": "{YELLOW}{WARNING_EMOJI}{RESET}",
    "ERROR_PREFIX": "{RED}{ERROR_EMOJI}{RESET}",
    "CRITICAL_PREFIX": "{RED}{CRITICAL_EMOJI}{RESET}",
}



# Logging
def apply_color_prefixes(style):
    replacements = {
        "{BLUE}": style["BLUE"],
        "{YELLOW}": style["YELLOW"],
        "{RED}": style["RED"],
        "{RESET}": style["RESET"],
        "{DEBUG_EMOJI}": style["DEBUG_EMOJI"],
        "{INFO_EMOJI}": style["INFO_EMOJI"],
        "{WARNING_EMOJI}": style["WARNING_EMOJI"],
        "{ERROR_EMOJI}": style["ERROR_EMOJI"],
        "{CRITICAL_EMOJI}": style["CRITICAL_EMOJI"],
    }

    def resolve(template: str) -> str:
        for token, value in replacements.items():
            template = template.replace(token, value)
        return template

    style["DEBUG_PREFIX"] = resolve(style["DEBUG_PREFIX"])
    style["INFO_PREFIX"] = resolve(style["INFO_PREFIX"])
    style["WARNING_PREFIX"] = resolve(style["WARNING_PREFIX"])
    style["ERROR_PREFIX"] = resolve(style["ERROR_PREFIX"])
    style["CRITICAL_PREFIX"] = resolve(style["CRITICAL_PREFIX"])

def ensure_config_dir():
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)

def write_config(config_data):
    ensure_config_dir()
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=4)
    return CONFIG_PATH

def load_config():
    """Load user config, merging with defaults."""
    config = DEFAULT_CONFIG.copy()
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            try:
                file_cfg = json.load(f)
                if isinstance(file_cfg, dict):
                    config.update(file_cfg)
            except json.JSONDecodeError:
                pass
    return config

# Logging
class CustomFormatter(logging.Formatter):
    def __init__(self, style):
        super().__init__()
        self.style = style

    def format(self, record):
        if record.levelno == logging.DEBUG:
            prefix = self.style["DEBUG_PREFIX"]
        elif record.levelno == logging.INFO:
            prefix = self.style["INFO_PREFIX"]
        elif record.levelno == logging.WARNING:
            prefix = self.style["WARNING_PREFIX"]
        elif record.levelno == logging.ERROR:
            prefix = self.style["ERROR_PREFIX"]
        elif record.levelno == logging.CRITICAL:
            prefix = self.style["CRITICAL_PREFIX"]
        else:
            prefix = ""
        return f"{prefix} {record.getMessage()}"

class PlainFormatter(logging.Formatter):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    def format(self, record):
        message = self.ansi_escape.sub('', record.getMessage())
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"[{timestamp}] {record.levelname}: {message}"

def setup_logging(config, style, cli_log_level=None):
    console_level_str = cli_log_level or config.get("LOG_LEVEL", LOG_LEVEL_DEFAULT)
    console_level = getattr(logging, console_level_str.upper(), logging.INFO)

    logger = logging.getLogger()

    if logger.handlers:
        for h in list(logger.handlers):
            logger.removeHandler(h)

    logger.setLevel(logging.DEBUG)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(CustomFormatter(style))
    logger.addHandler(console_handler)

    # Rotating file handler using config values
    log_file_path = os.path.join(CONFIG_DIR, f"{APPLICATION_NAME}.log")
    file_handler = RotatingFileHandler(
        log_file_path,
        mode="a",
        maxBytes=int(config.get("MAX_BYTES", 500_000)),
        backupCount=int(config.get("BACKUP_COUNT", 5)),
        encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(PlainFormatter())
    logger.addHandler(file_handler)

    return logger, log_file_path

def tail_log(log_file_path, lines=200):
    if not os.path.exists(log_file_path):
        print(f"Log file not found: {log_file_path}")
        return
    with open(log_file_path, "r", encoding="utf-8") as f:
        all_lines = f.readlines()
        for line in all_lines[-lines:]:
            print(line.rstrip())

def handle_log_option(args, log_file_path):
    if args.log:
        tail_log(log_file_path, lines=200)
        sys.exit(0)


def configure_logging(args, config):
    """Prepare logging style and logger."""
    style = LOG_STYLE.copy()
    apply_color_prefixes(style)
    ensure_config_dir()
    cli_level = "DEBUG" if args.debug else args.log_level
    logger, log_file_path = setup_logging(config, style, cli_log_level=cli_level)
    return logger, log_file_path

# Args
def parse_args():
    parser = argparse.ArgumentParser(description="Template script with configurable logging.")
    parser.add_argument(
        "target",
        help="Target IP address or CIDR notation."
    )
    parser.add_argument(
        "-log-level",
        type=str.upper,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the console logging level (file logging is always DEBUG)."
    )
    parser.add_argument(
        "-debug", "-v",
        action="store_true",
        help="Shortcut for -log-level DEBUG."
    )
    parser.add_argument(
        "-log",
        action="store_true",
        help="Show the last 200 lines of the log file and exit."
    )
    parser.add_argument(
        "-u", "--username",
        dest="username",
        type=str,
        default="",
        help="Username for authentication."
    )
    parser.add_argument(
        "-p", "--password",
        dest="password",
        type=str,
        default="",
        help="Password for authentication."
    )
    parser.add_argument(
        "-H", "--hash",
        dest="hash",
        type=str,
        default="",
        help="Hash for authentication."
    )
    parser.add_argument(
        "-t", "--ticket", "--use-kcache",
        dest="ticket",
        action="store_true",
        help="Use Kerberos cache (kcache) for authentication."
    )
    parser.add_argument(
        "-x", "--proxychains",
        dest="proxychains",
        action="store_true",
        help="Use proxychains when running commands."
    )
    parser.add_argument(
        "-d", "--domain",
        dest="domain",
        type=str,
        default="",
        help="Domain for authentication."
    )
    parser.add_argument(
        "-l", "--local-auth",
        dest="local_auth",
        action="store_true",
        help="Use local authentication."
    )
    parser.add_argument(
        "-s", "--services",
        dest="services",
        type=lambda value: [item.strip().lower() for item in value.split(",") if item.strip()],
        default=DEFAULT_SERVICES,
        help="Comma-separated list of services to discover and scan (default: smb,mssql,wmi,winrm)."
    )
    parser.add_argument(
        "-o", "-outputdir",
        dest="outputdir",
        type=str,
        help=f"Specify a custom base directory for the output folder. The script will create '{APPLICATION_NAME}' inside this path."
    )
    return parser.parse_args()

# Output Directory
def ensure_output_dir(config):
    output_dir = config["OUTPUT_DIR"]
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    return output_dir

def resolve_output_dir(args, config):
    """
    Determine and set the OUTPUT_DIR based on CLI arguments or defaults.
    """
    if args.outputdir:
        base_dir = os.path.abspath(os.path.expanduser(os.path.expandvars(args.outputdir)))
        config["OUTPUT_DIR"] = os.path.join(base_dir, APPLICATION_NAME)
    else:
        config["OUTPUT_DIR"] = os.path.join(os.getcwd(), APPLICATION_NAME)
    return config["OUTPUT_DIR"]


def prepare_output_dir(args, config):
    """Resolve, persist, and ensure the output directory exists."""
    output_dir = resolve_output_dir(args, config)
    write_config(config)
    return ensure_output_dir(config)


# Main
def main():
    args = parse_args()
    config = load_config()
    logger, log_file_path = configure_logging(args, config)
    handle_log_option(args, log_file_path)
    output_dir = prepare_output_dir(args, config)

    args.target = normalize_target(args.target)
    logger.debug(f"Output directory ready: {output_dir}")
    logger.debug(f"Using config path: {CONFIG_PATH}")
    logger.debug(f"Using Logging path: {log_file_path}")
    logger.debug(f"Parsed args: {args}")

    service_hosts = discover_service_hosts(args.target, args.services, logger)
    write_service_discovery_files(service_hosts, output_dir, logger)
    run_nxc_on_discovered_hosts(service_hosts, args, output_dir, logger)

    logger.info("Service discovery and targeted nxc scan complete.")

    logger.debug("Completing Script Execution.")

if __name__ == "__main__":
    main()
