# BetterBlih

## What is it
BetterBlih is an improved version of the `blih` program to manage your Epitech Git repositories.

## Installation
You need [Python 3.6+](https://docs.python.org/3.6/tutorial/index.html) to run this program. You can install the dependencies through PyPI: `python3 -m pip install --user -r requirements.txt`

If you want to you can install this program with the `install.sh` script (for Linux), it installs BetterBlih to `/usr/local/bin`.

```sh
sudo ./install.sh
```
You can also uninstall it in the same way using the `uninstall.sh` script.
```sh
sudo ./uninstall.sh
```

## Configuration
You can set the `BETTERBLIH_LOGIN` environment variable with your Epitech login (firstname.lastname@epitech.eu) to automatically fill in this information.

## How to use it
When you run the program it will prompt you for your Epitech login and password, then you will be able to enter any of these commands (this is the output of the `help` command):
```
help                       show this message

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

exit, quit, logout         exit BetterBlih
```
