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

# Prepend the hook to /etc/pam.d/gdm-password
pam_file="/etc/pam.d/gdm-password"
hook_line="auth required pam_exec.so expose_authtok quiet ${ndauthhook}"


if ! grep -Fxq "$hook_line" "$pam_file"; then
    echo "Adding authentication hook to $pam_file"
    sed -i "1i $hook_line" "$pam_file"
else
    echo "Authentication hook already present in $pam_file"
fi

