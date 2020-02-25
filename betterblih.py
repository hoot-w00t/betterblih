#!/usr/bin/python3

"""
    BetterBlih
    Copyright (C) 2019-2020  akrocynova

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""

from sys import exit
from os import getenv
from json import loads as json_load, dumps as json_dump
from getpass import getpass
from hashlib import sha512
from requests import request as http_request
from requests.exceptions import SSLError
from urllib3 import disable_warnings as disable_ssl_warnings
from datetime import datetime
import hmac

class acolor:
    blue   = '\033[94m'
    green  = '\033[92m'
    yellow = '\033[93m'
    red    = '\033[91m'
    violet = '\33[35m'
    reset  = '\033[0m'
    bold   = '\033[1m'

class BetterBlih:
    def __init__(self, blih_url: str = "https://blih.epitech.eu", verify_ssl: bool = True, debug: bool = False):
        self.version = "1.1"
        self.blih_url = blih_url
        self.debug = debug
        self.verify_ssl = verify_ssl
        self.user_login = None
        self.user_token = None

        if not verify_ssl:
            disable_ssl_warnings()

    def logged_in(self):
        return self.user_token != None

    def login(self, _login: str, _password: str):
        self.user_login = _login
        self.user_token = sha512(_password.encode("utf-8")).hexdigest()

        if self.whoami() == self.user_login:
            return True
        else:
            self.user_login = None
            self.user_token = None
            return False

    def logout(self):
        self.user_login = None
        self.user_token = None
        return True

    def sign_data(self, data: dict = None):
        sig = hmac.new(
            bytes(self.user_token.encode("utf-8")),
            msg=self.user_login.encode("utf-8"),
            digestmod=sha512
            )
        if data != None:
            sig.update(json_dump(
                data,
                indent=4,
                sort_keys=True
                ).encode("utf-8"))

        signed_data = {
            "user": self.user_login,
            "signature": sig.hexdigest(),
        }
        if data != None:
            signed_data["data"] = data

        return json_dump(signed_data).encode("utf-8")

    def blih_request(self, path: str, method="GET", data: dict = None):
        req_url = f"{self.blih_url}{path}"

        try:
            data = self.sign_data(data)
            if self.debug:
                print(f"{method} request to {req_url} with data:\n{data.decode('utf-8')}")

            req = http_request(
                method,
                req_url,
                data=data,
                verify=self.verify_ssl,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"betterblih-{self.version}",
                })

        except SSLError as e:
            print(f"SSL error: {e}")
            return None

        except Exception as e:
            print(f"Blih request error: {e}")
            return None

        try:
            return json_load(req.content.decode("utf-8"))

        except Exception as e:
            print(f"Could not decode JSON from response: {e}")
            return None

    def whoami(self):
        response = self.blih_request("/whoami")
        try:
            return response["message"]
        except:
            return None

    def repo_create(self, name: str, description: str = None):
        data = {
            "name": name,
            "type": "git",
        }
        if description != None:
            data["description"] = description

        response = self.blih_request("/repositories", method="POST", data=data)
        try:
            if response.get("error") != None:
                return (False, response["error"])
            else:
                return (True, response["message"])

        except Exception as e:
            return (False, str(e))

    def repo_delete(self, name: str):
        response = self.blih_request(f"/repository/{name}", method="DELETE")
        try:
            if response.get("error") != None:
                return (False, response["error"])
            else:
                return (True, response["message"])

        except Exception as e:
            return (False, str(e))

    def repo_getacl(self, name: str):
        response = self.blih_request(f"/repository/{name}/acls")

        try:
            if response.get("error") != None:
                return (False, response["error"])
            else:
                return (True, response)

        except Exception as e:
            return (False, str(e))

    def repo_setacl(self, name: str, username: str, acls: str):
        data = {
            "user": username,
            "acl": acls,
        }

        response = self.blih_request(f"/repository/{name}/acls", method="POST", data=data)
        try:
            if response.get("error") != None:
                return (False, response["error"])
            else:
                return (True, response["message"])

        except Exception as e:
            return (False, str(e))

    def repo_info(self, repository):
        response = self.blih_request(f"/repository/{repository}")
        try:
            return response["message"]
        except:
            return None

    def repo_list(self):
        response = self.blih_request("/repositories")
        try:
            return response["repositories"]
        except:
            return None

    def sshkey_upload_file(self, pubkey_file: str):
        try:
            with open(pubkey_file, 'r') as h:
                key = h.read().strip()

            return self.sshkey_upload(key)

        except Exception as e:
            return (False, str(e))

    def sshkey_upload(self, key: str):
        data = {
            "sshkey": key,
        }

        response = self.blih_request("/sshkeys", method="POST", data=data)
        try:
            if response.get("error") != None:
                return (False, response["error"])
            else:
                return (True, response["message"])

        except Exception as e:
            return (False, str(e))

    def sshkey_delete(self, key: str):
        response = self.blih_request(f"/sshkey/{key}", method="DELETE")
        try:
            if response.get("error") != None:
                return (False, response["error"])
            else:
                return (True, response["message"])

        except Exception as e:
            return (False, str(e))

    def sshkey_list(self):
        response = self.blih_request("/sshkeys")
        try:
            if response.get("error") != None:
                return (False, response["error"])
            else:
                return (True, response)

        except Exception as e:
            return (False, str(e))


def list_repos(_blih: BetterBlih):
    r = _blih.repo_list()
    if r == None:
        print(f"{acolor.red}No repositories found.{acolor.reset}")

    else:
        repos = []
        for repo in r:
            repos.append(repo)
        repos.sort()

        print(f"{len(repos)} repositories:")
        print(f"{acolor.blue}{f'{acolor.reset}, {acolor.blue}'.join(repos)}{acolor.reset}")

def list_sshkeys(_blih: BetterBlih, full: bool = False):
    r = _blih.sshkey_list()
    if r[0]:
        print(f"{len(r[1])} SSH keys:")
        for key in r[1]:
            if full:
                print(f"    {key} ({acolor.blue}{r[1][key]}{acolor.reset})")
            else:
                print(f"    {key}")

    else:
        print(f"{acolor.red}{r[1]}{acolor.reset}")

def repo_create(_blih: BetterBlih, name: str = None):
    if name == None:
        name = input("Name of the repository: ")

    r = _blih.repo_create(name)
    if r[0]:
        print(f"{acolor.green}{r[1]}{acolor.reset}")
    else:
        print(f"{acolor.red}{r[1]}{acolor.reset}")

def repo_delete(_blih: BetterBlih, name: str = None):
    if name == None:
        name = input("Repository: ")

    if not input(f"{acolor.red}Delete {acolor.bold}{name}{acolor.reset}{acolor.red}, are you sure? (y/N) ").lower() in ["yes", "y"]:
        print(f"{acolor.red}Cancelled.{acolor.reset}")
        return

    r = _blih.repo_delete(name)
    if r[0]:
        print(f"{acolor.green}{r[1]}{acolor.reset}")
    else:
        print(f"{acolor.red}{r[1]}{acolor.reset}")

def repo_info(_blih: BetterBlih, name: str = None):
    if name == None:
        name = input("Repository: ")

    repo = _blih.repo_info(params[2])
    if repo == None:
        print(f"{acolor.red}Repository could not be found.{acolor.reset}")

    else:
        print(f"{acolor.blue}{repo['url']}{acolor.reset} ({acolor.violet}{repo['uuid']}{acolor.reset})")
        creation_date = datetime.fromtimestamp(int(repo["creation_time"]))
        print(f"Created on {acolor.green}{creation_date.strftime('%Y-%m-%d %H:%M:%S')}{acolor.reset}")

def repo_getacl(_blih: BetterBlih, name: str = None):
    if name == None:
        name = input("Repository: ")

    r = _blih.repo_getacl(name)
    if r[0]:
        for user in r[1]:
            acls = r[1][user]
            acls_ext = []
            for acl in acls:
                if acl == 'a':
                    acls_ext.append(f"{acolor.red}is an administrator{acolor.reset}")
                elif acl == 'r':
                    acls_ext.append(f"{acolor.green}can read{acolor.reset}")
                elif acl == 'w':
                    acls_ext.append(f"{acolor.yellow}can write{acolor.reset}")

            print(f"{acolor.blue}{user}{acolor.reset}: {', '.join(acls_ext)} ({acolor.blue}{acls}{acolor.reset})")

    else:
        print(f"{acolor.red}{r[1]}{acolor.reset}")

def repo_setacl(_blih: BetterBlih, name: str = None, usernames: list = None, acls: str = None):
    if name == None:
        name = input("Repository: ")

    if acls == None:
        desired_acls = []
        if input(f"Grant reading permission? ({acolor.green}yes{acolor.reset}/{acolor.red}no{acolor.reset}) ").lower() in ["yes", "y"]:
            desired_acls.append('r')
        if input(f"Grant writing permission? ({acolor.green}yes{acolor.reset}/{acolor.red}no{acolor.reset}) ").lower() in ["yes", "y"]:
            desired_acls.append('w')
        if input(f"Make users administrators? ({acolor.green}yes{acolor.reset}/{acolor.red}no{acolor.reset}) ").lower() in ["yes", "y"]:
            desired_acls.append('a')

        if len(desired_acls) == 0:
            pmsg = f"The users will have no permissions"
        else:
            pmsg = f"The users will have these permissions: {acolor.blue}{''.join(desired_acls)}{acolor.reset}"

        if not input(f"{pmsg}, continue? (y/N) ").lower() in ["yes", "y"]:
            print(f"{acolor.red}Cancelled.{acolor.reset}")
            return

        acls = ''.join(desired_acls)

    if usernames == None:
        usernames = []
        _usernames = input("Users to apply permissions for: ")
        for username in _usernames.split(','):
            usernames.append(username.strip())

        if not input(f"Apply permissions for: {acolor.blue}{f'{acolor.reset}, {acolor.blue}'.join(usernames)}{acolor.reset} (y/N) ").lower() in ["yes", "y"]:
            print(f"{acolor.red}Cancelled.{acolor.reset}")
            return

    for username in usernames:
        r = _blih.repo_setacl(name, username, acls)
        if r[0]:
            print(f"{acolor.blue}{username}{acolor.reset}: {acolor.green}{r[1]}{acolor.reset}")
        else:
            print(f"{acolor.blue}{username}{acolor.reset}: {acolor.red}{r[1]}{acolor.reset}")

def repo_resetacl(_blih: BetterBlih, name: str = None):
    if name == None:
        name = input("Repository: ")

    r = _blih.repo_getacl(name)
    if r[0]:
        users = []
        for user in r[1]:
            users.append(user)

        if not input(f"Reset permissions for: {acolor.blue}{f'{acolor.reset}, {acolor.blue}'.join(users)}{acolor.reset}, are you sure? (y/N) ").lower() in ["yes", "y"]:
            print(f"{acolor.red}Cancelled.{acolor.reset}")
            return

        for user in users:
            r = _blih.repo_setacl(name, user, "")
            if not r[0]:
                print(f"{acolor.blue}{user}{acolor.reset}: {acolor.red}{r[1]}{acolor.reset}")

        print(f"{acolor.green}Permissions reset for {acolor.bold}{name}{acolor.reset}")

    else:
        print(f"{acolor.red}{r[1]}{acolor.reset}")

def sshkey_upload(_blih: BetterBlih, pubkey_file: str = None):
    if pubkey_file == None:
        pubkey_file = input("Path to the SSH public key: ")

    r = _blih.sshkey_upload_file(pubkey_file)
    if r[0]:
        print(f"{acolor.green}{r[1]}{acolor.reset}")
    else:
        print(f"{acolor.red}{r[1]}{acolor.reset}")

def sshkey_delete(_blih: BetterBlih, key: str = None):
    if key == None:
        keys = _blih.sshkey_list()
        if keys == None:
            print("You haven't uploaded any SSH keys.")
            return
        if not keys[0]:
            print("You haven't uploaded any SSH keys.")
            return
        if len(keys[1]) == 0:
            print("You haven't uploaded any SSH keys.")
            return

        key_list = []
        index = 1
        for _key in keys[1]:
            key_list.append(_key)
            print(f"{index}: {_key}")
            index += 1

        try:
            choice = int(input("Which key to delete? "))
            key = key_list[choice - 1]

        except:
            print(f"{acolor.red}Invalid input.{acolor.reset}")
            return

    if not input(f"{acolor.red}Delete {acolor.bold}{key}{acolor.reset}{acolor.red}, are you sure? (y/N) ").lower() in ["yes", "y"]:
        print(f"{acolor.red}Cancelled.{acolor.reset}")
        return

    r = _blih.sshkey_delete(key)
    if r[0]:
        print(f"{acolor.green}{r[1]}{acolor.reset}")
    else:
        print(f"{acolor.red}{r[1]}{acolor.reset}")

if __name__ == "__main__":
    from signal import signal, SIGINT
    from argparse import ArgumentParser
    from time import sleep
    import readline

    def exit_signal(sig, frame):
        print()
        exit(2)

    signal(SIGINT, exit_signal)

    help_message = """help                       show this message

list
    repos                  display a list of your repositories
    sshkeys [-f]           display a list of your SSH keys

    -f                     (optionnal) display more information

repo
    create [repo]          create a repository
    delete [repo]          delete a repository
    info [repo]            show information about a repository
    getacl [repo]          display a repository's permissions
    setacl [repo] [acl]    set permissions on a repository
           [user(s)]       multiple users should be separated using a comma (user, user2, ...)
    resetacl [repo]        reset all permissions from all users on a repository

    prepare [repo]         create a repository and apply ACL for ramassage-tek

sshkey
    upload [file]          upload an SSH key
    delete [key]           delete an SSH key

whoami                     display your login

exit, quit, logout         exit BetterBlih"""

    arg_parser = ArgumentParser(description="BetterBlih")
    arg_parser.add_argument(
        "-d", "--debug",
        dest="debug",
        action="store_true",
        help="Display debugging information"
        )
    arg_parser.add_argument(
        "-u", "--url",
        dest="blih_url",
        default="https://blih.epitech.eu",
        type=str,
        help="Specify a custom Blih URL"
        )
    arg_parser.add_argument(
        "--no-env",
        dest="no_env",
        action="store_true",
        help="Disable grabbing information from the environment"
        )
    arg_parser.add_argument(
        "--max-retry",
        dest="max_retry",
        default=3,
        type=int,
        help="Maximum authentication attempts before exitting (default: 3)"
        )
    arg_parser.add_argument(
        "--infinite-retry",
        dest="infinite_retry",
        action="store_true",
        help="Infinite authentication attempts"
        )
    arg_parser.add_argument(
        "--no-verify-ssl",
        dest="no_verify_ssl",
        action="store_true",
        help="Disable SSL certificate verification"
        )
    args = arg_parser.parse_args()

    if args.blih_url.endswith("/"):
        args.blih_url = args.blih_url.rstrip("/")

    if args.no_verify_ssl:
        if not input(f"{acolor.red}{acolor.bold}Warning{acolor.reset}{acolor.red}: Turning off SSL verification can be dangerous, are you sure? [y/N]{acolor.reset} ").lower() in ["yes", "y"]:
            exit(1)

    if args.debug:
        print(f"Using Blih URL: {args.blih_url}")


    blih = BetterBlih(blih_url=args.blih_url, debug=args.debug, verify_ssl=not args.no_verify_ssl)

    login = getenv("BETTERBLIH_LOGIN", default=None)
    if login == None or args.no_env:
        login = input("Epitech login: ")
    else:
        print(f"Login as: {login}")

    retry = 0
    while not blih.logged_in():
        password = getpass(prompt="Epitech password: ")
        print("...", end='\r')
        if not blih.login(login, password):
            retry += 1
            if retry < args.max_retry or args.infinite_retry:
                print(f"{acolor.red}Authentication failed, check your login and password.{acolor.reset}")
                sleep(1)
            else:
                print(f"{acolor.red}{retry} failed attempt{'s' if retry > 1 else ''}, exitting.{acolor.reset}")
                exit(1)

    print(f"{acolor.green}Authenticated as {acolor.bold}{blih.user_login}{acolor.reset}.")
    print(f"Feeling lost? Enter '{acolor.blue}help{acolor.reset}'.\n")

    readline.clear_history()
    prompt = f"{acolor.red if args.no_verify_ssl else acolor.yellow}betterblih $>{acolor.reset} "
    while blih.logged_in():
        try:
            user_input = input(prompt).strip()
            if len(user_input) == 0:
                continue

            params = user_input.split()
            param_count = len(params)
            command = params[0]

            if command == "exit" or command == "quit" or command == "logout":
                blih.logout()

            elif command == "help":
                print(help_message)

            elif command == "list":
                if param_count < 2:
                    continue

                elif params[1] == "repos":
                    list_repos(blih)

                elif params[1] == "sshkeys":
                    if param_count >= 3:
                        if params[2] == "-f":
                            list_sshkeys(blih, full=True)
                            continue
                    list_sshkeys(blih)

                else:
                    raise Exception(f"{acolor.red}Invalid option:{acolor.blue} {params[1]}{acolor.reset}")

            elif command == "repo":
                if param_count < 2:
                    continue

                elif params[1] == "create":
                    if param_count >= 3:
                        repo_create(blih, params[2])
                    else:
                        repo_create(blih)

                elif params[1] == "delete":
                    if param_count >= 3:
                        repo_delete(blih, params[2])
                    else:
                        repo_delete(blih)

                elif params[1] == "info":
                    if param_count >= 3:
                        repo_info(blih, params[2])
                    else:
                        repo_info(blih)

                elif params[1] == "getacl":
                    if param_count >= 3:
                        repo_getacl(blih, params[2])
                    else:
                        repo_getacl(blih)

                elif params[1] == "setacl":
                    p_name = None
                    p_acls = None
                    p_usernames = None
                    if param_count >= 3 : p_name = params[2]
                    if param_count >= 4 : p_acls = params[3]
                    if param_count >= 5:
                        p_usernames = []
                        for username in ' '.join(params[4:]).split(','):
                            p_usernames.append(username.strip())

                    repo_setacl(blih, name=p_name, usernames=p_usernames, acls=p_acls)

                elif params[1] == "resetacl":
                    p_name = None
                    if param_count >= 3 : p_name = params[2]

                    repo_resetacl(blih, name=p_name)

                elif params[1] == "prepare":
                    if param_count >= 3:
                        p_name = params[2]
                    else:
                        p_name = input("Name of the repository: ")

                    repo_create(blih, p_name)
                    repo_setacl(blih, p_name, ["ramassage-tek"], "r")
                    repo_getacl(blih, p_name)

                else:
                    raise Exception(f"{acolor.red}Invalid option:{acolor.blue} {params[1]}{acolor.reset}")

            elif command == "sshkey":
                if param_count < 2:
                    continue

                elif params[1] == "upload":
                    if param_count >= 3:
                        sshkey_upload(blih, params[2])
                    else:
                        sshkey_upload(blih)

                elif params[1] == "delete":
                    if param_count >= 3:
                        sshkey_delete(blih, params[2])
                    else:
                        sshkey_delete(blih)

                else:
                    raise Exception(f"{acolor.red}Invalid option:{acolor.blue} {params[1]}{acolor.reset}")

            elif command == "whoami":
                r = blih.whoami()
                if r == None:
                    print(f"{acolor.red}Nothing was returned.{acolor.reset}")
                else:
                    print(f"You are: {acolor.green}{r}{acolor.reset}")

            else:
                print(f"{acolor.red}Unknown command: {acolor.blue}{' '.join(params)}{acolor.reset}")

        except Exception as e:
            print(e)

    exit(0)
