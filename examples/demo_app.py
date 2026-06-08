from __future__ import annotations

import subprocess


def run_command(user_input: str):
    return subprocess.run(user_input, shell=True)
