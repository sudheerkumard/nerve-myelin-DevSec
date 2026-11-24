# AI assistant service: LLM security benchmark (VULN lines must be reported, SAFE lines must not)
import json
import os
import subprocess

import joblib
from flask import request
from langchain.agents import load_tools
from langchain_experimental.tools import PythonREPLTool


def run_generated(client):
    completion = client.chat(messages=[{"role": "user", "content": "write code"}])
    exec(completion.text)                                                      # VULN NM-AI-006
    data = json.loads(completion.text)                                         # SAFE parsed, not executed
    return data


def shell_from_model(answer):
    subprocess.run(answer, shell=True)                                         # VULN NM-AI-008
    subprocess.run(["ls", "-l"], check=True)                                   # SAFE constant command


def sql_from_model(cursor, response):
    cursor.execute(f"SELECT * FROM orders WHERE id = {response}")              # VULN NM-AI-009
    cursor.execute("SELECT * FROM orders WHERE id = %s", (response,))          # SAFE parameterised


def build_prompt():
    system_prompt = f"You are a helpful bank assistant. Customer says: {request.args['q']}"   # VULN NM-AI-013
    return [{"role": "system", "content": "You are a helpful bank assistant."}]              # SAFE constant system prompt


tools = [PythonREPLTool()]                                                     # VULN NM-AI-011
safe_tools = load_tools(["wikipedia"])                                         # SAFE read-only tool


def leak_env(client):
    return client.chat(messages=[{"role": "user", "content": str(os.environ)}])   # VULN NM-AI-016


def load_model():
    return joblib.load("models/churn_model.pkl")                               # VULN NM-AI-020


def pick_model(client):
    return client.chat(model=request.args.get("model"), messages=[])          # VULN NM-AI-018
