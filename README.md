
# goPass

A password management system written in go.

**I am not responsible for the safety of your passwords. I am not a security professional, this is only a hobby project.**

## Usage

### Setup

To use goPass just build the goPass.go file and execute it. The first time you execute the file it will ask you to create a new password and create a data.json afterwards. In this file all your password will be stored encoded.

### Important commands

To add a password use the add-command and fill out the required informations. To get the password back use the get-command with the password name after it. If you forgot a password name use the list-command to display all the password names you stored in goPass. To delete a password use the del-command with the password name following it. If you want to close down goPass use the end-command.

### Settings

To change the settings use the settings-command followed by the setting you want to change. You can specify weather you want to be asked twice before deleting a password using the askTwice-keyword with true of false following it. To change the number of times you want to get kicked out of goPass after using a wrong password when logging in use the numWrongPW-keyword followed by the number. You can also change this to a negative number to never be kicked out.

## Additioal information

If you find yourself using goPass very often you may want to add a [AutoHotkey](https://www.autohotkey.com/)-script to open it using a keyboard shortcut.