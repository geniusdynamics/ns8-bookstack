#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Find, check and generate the Laravel APP_KEY of BookStack.

The key encrypts data such as MFA secrets: an existing valid key must never
be replaced, or that data cannot be decrypted any more.
"""

import base64
import os
import subprocess

import agent


def generate_laravel_app_key():
    return "base64:" + base64.b64encode(os.urandom(32)).decode("utf-8")


def is_valid_laravel_app_key(value):
    """AES-256-CBC needs exactly 32 bytes: "base64:<32 bytes>" or a 32-character string."""
    if value.startswith("base64:"):
        try:
            return len(base64.b64decode(value[7:], validate=True)) == 32
        except ValueError:
            return False
    return len(value) == 32


def app_key_from_volume():
    """A valid key an administrator put into /config/www/.env by hand, if any."""
    try:
        mountpoint = subprocess.run(
            ["podman", "volume", "inspect", "bookstack-app", "--format", "{{.Mountpoint}}"],
            capture_output=True, text=True, check=True).stdout.strip()
        with open(os.path.join(mountpoint, "www", ".env")) as envfile:
            for line in envfile:
                if line.startswith("APP_KEY="):
                    value = line.split("=", 1)[1].strip().strip('"')
                    return value if is_valid_laravel_app_key(value) else ""
    except (OSError, subprocess.CalledProcessError):
        pass
    return ""


def app_key_from_envfile(name):
    if not os.path.exists(name):
        return ""
    value = agent.read_envfile(name).get("APP_KEY", "")
    return value if is_valid_laravel_app_key(value) else ""


def find_app_key():
    """The first valid key of app-db.env, app.env and the volume, else a new one.

    Release 1.2.0 stored an invalid 64-character key in app-db.env; app.env or
    the volume may still hold the valid key the instance runs with.
    """
    return (app_key_from_envfile("app-db.env")
            or app_key_from_envfile("app.env")
            or app_key_from_volume()
            or generate_laravel_app_key())


def store_app_key(app_key):
    """Write the key into app-db.env (the source) and app.env (read by the container)."""
    for name in ("app-db.env", "app.env"):
        if os.path.exists(name):
            values = agent.read_envfile(name)
            if values.get("APP_KEY") != app_key:
                values["APP_KEY"] = app_key
                agent.write_envfile(name, values)
