import os
import argparse
from ipaddress import ip_network
import re
from colorama import init, Fore
import subprocess

init(autoreset=True)

def run_nxc(protocol, target, output_directory, username='', password='', hash='', ticket='', domain='', use_proxychains=False, local_auth=False):
    if not username and not ticket:
        username = "''"
        password = "''"

    command = 'proxychains -q ' if use_proxychains else ''
    command += f'nxc {protocol} {target}'
    if username:
        command += f' -u {username}'
    if password:
        command += f' -p {password}'
    if hash:
        command += f' -H {hash}'
    if ticket:
        command += f' --use-kcache'
    if domain:
        command += f' -d {domain}'
    if local_auth:
        command += ' --local-auth'
    return command

def print_protocol_completed(protocol):
    print(f'{Fore.LIGHTBLACK_EX}{protocol} scan completed.{Fore.RESET}')

def convert_cidr_to_filename(cidr, username='', domain=''):
    filename = cidr.replace('/', '-')
    if username:
        filename += f'-{username}'
    if domain:
        filename += f'-{domain.replace(".", "-")}'
    return filename

def run_protocol(protocol, target, output_directory, username, password, hash_value, ticket, domain, use_proxychains, local_auth):
    command = run_nxc(protocol, target, output_directory, username, password, hash_value, ticket, domain, use_proxychains, local_auth)

    cidr_filename = convert_cidr_to_filename(target, username, domain)

    output_file = f'nxc-{protocol}-{cidr_filename}.txt'

    with open(output_file, 'w') as f:
        f.write(f'\n\n{Fore.BLUE}Command run to generate this output:\n{Fore.RESET}{Fore.LIGHTYELLOW_EX}{command}{Fore.RESET}\n')

    os.system(f'{command} 2>/dev/null | tee -a {output_file} > /dev/null')

    with open(output_file, 'r') as f:
        file_content = f.read()

    modified_content = highlight_pwned_lines(file_content, username, domain)

    with open(output_file, 'w') as f:
        f.write(modified_content)

    print_protocol_completed(protocol)


def highlight_pwned_lines(file_content, username, domain):
    lines = file_content.split('\n')
    highlighted_lines = []

    for line in lines:
        if username in line and "(Pwn3d!)" in line:
            highlighted_lines.append(f"{Fore.LIGHTMAGENTA_EX}{line}{Fore.RESET}")
        else:
            highlighted_lines.append(line)

    return '\n'.join(highlighted_lines)

def process_output_files(output_directory, protocols, target, username, domain, local_auth):
    smb_protocol_processed = False

    for protocol in protocols:
        cidr_filename = convert_cidr_to_filename(target, username, domain)
        output_file = f'nxc-{protocol}-{cidr_filename}.txt'

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                file_content = f.read()

            if protocol.lower() == 'smb':
                smb_protocol_processed = True

            smb_ip_addresses = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', file_content)

            for smb_ip in smb_ip_addresses:
                smb_protocol = 'smb'
                smb_command = run_nxc(smb_protocol, smb_ip, output_directory, username, password, hash_value, ticket, domain, use_proxychains, local_auth)

                if smb_protocol.lower() == 'smb':
                    smb_command += ' --shares'

                smb_output_file = f'nxc-{smb_protocol}-{cidr_filename}-{smb_ip}--shares.txt'

                with open(smb_output_file, 'w') as f:
                    f.write(f'\n\n{Fore.BLUE}Command run to generate this output:\n{Fore.RESET}{Fore.LIGHTYELLOW_EX}{smb_command}{Fore.RESET}\n')

                subprocess.run(f'{smb_command} 2>/dev/null | tee -a {smb_output_file} > /dev/null', shell=True)

            if smb_protocol.lower() == 'smb' and smb_protocol_processed:
                break

            if smb_protocol.lower() == 'smb':
                smb_protocol_processed = True

            print_protocol_completed(protocol)
                        


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Helper script for running netexec variations')
    parser.add_argument('target', help='Target IP address or CIDR notation')
    parser.add_argument('-u', '--username', help='Username for authentication', default='')
    parser.add_argument('-p', '--password', help='Password for authentication', default='')
    parser.add_argument('-H', '--hash', help='Hash for LDAP', default='')
    parser.add_argument('-t', '-k', '--ticket', action='store_true', help='Use kcache for authentication')
    parser.add_argument('-d', '--domain', help='Domain for authentication', default='')
    parser.add_argument('-x', '--proxychains', action='store_true', help='Use proxychains')
    parser.add_argument('-l', '--local-auth', action='store_true', help='Use local authentication')

    args = parser.parse_args()

    target = args.target
    username = args.username
    password = args.password
    hash_value = args.hash
    ticket = args.ticket
    domain = args.domain
    use_proxychains = args.proxychains

    if not args.username and not args.ticket:
        username = ''
        password = ''

    if '/' not in target:
        target = f'{target}/32'

    protocols = ['ftp', 'ldap', 'mssql', 'rdp', 'smb', 'ssh', 'vnc', 'winrm', 'wmi']

    print(f'{Fore.LIGHTWHITE_EX}NXC Scans Initiated.{Fore.RESET}')
    output_directory = os.path.join(os.getcwd(), 'nxc-output')
    os.makedirs(output_directory, exist_ok=True)

    os.chdir(output_directory)

    for protocol in protocols:
        run_protocol(protocol, target, output_directory, username, password, hash_value, ticket, domain, use_proxychains, args.local_auth)

    process_output_files(output_directory, protocols, target, username, domain, args.local_auth)

    print(f'{Fore.LIGHTBLACK_EX}smb shares scans completed.{Fore.RESET}')
    print(f'{Fore.LIGHTWHITE_EX}nxc scans completed.{Fore.RESET}')
