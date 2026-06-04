#!/bin/bash
# Run from the script's own directory and use the venv interpreter explicitly.
# (sudo resets PATH and drops any activated venv, so $(which python) is unreliable.)
cd "$(dirname "$0")"
sudo nids_env/bin/python main.py
