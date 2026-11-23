# Databricks notebook source
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# ruff: noqa: F821, I001

import shutil
from pathlib import Path


SKILL_NAME = "what-can-i-do-in-databricks"

source = Path.cwd() / SKILL_NAME
if not (source / "SKILL.md").is_file():
    raise FileNotFoundError(
        f"Could not find {SKILL_NAME}/SKILL.md under {Path.cwd()}. "
        "Run this notebook from the repository root."
    )

username = spark.sql("SELECT current_user()").first()[0]
skills_directory = Path("/Workspace/Users") / username / ".assistant" / "skills"
destination = skills_directory / SKILL_NAME

skills_directory.mkdir(parents=True, exist_ok=True)
shutil.copytree(source, destination, dirs_exist_ok=True)

print(f"Installed {SKILL_NAME} to /Users/{username}/.assistant/skills/{SKILL_NAME}/")
print("Start a new Genie Code chat to use the installed skill.")
