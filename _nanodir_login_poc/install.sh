#!/bin/bash

# Check if user is root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit
fi

# Assuming ndauthhook.py is in /usr/local/bin
ndauthhook="/usr/local/bin/ndauthhook.py"

chmod +x "$ndauthhook"
chown root:root "$ndauthhook"

# Prepend the hook to /etc/pam.d/gdm-passwd
pam_file="/etc/pam.d/gdm-passwd"
hook_line="auth optional pam_exec.so ${ndauthhook}"

if ! grep -Fxq "$hook_line" "$pam_file"; then
    echo "$hook_line" | cat - "$pam_file" > temp && mv temp "$pam_file"
    echo "Hook added to $pam_file"
else
    echo "Hook already present in $pam_file"
fi

