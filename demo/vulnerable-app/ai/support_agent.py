"""Customer support agent (sample: intentionally vulnerable)."""
import os
import subprocess

from flask import request
from langchain_experimental.tools import PythonREPLTool


def answer(client):
    system_prompt = f"You are the Acme support bot. Customer question: {request.args['q']}"
    completion = client.chat(messages=[{"role": "system", "content": system_prompt}])
    return completion.text


def run_suggested_fix(client):
    response = client.chat(messages=[{"role": "user", "content": "give me a shell command to clean temp files"}])
    subprocess.run(response.text, shell=True)


def debug_context(client):
    return client.chat(messages=[{"role": "user", "content": str(os.environ)}])


tools = [PythonREPLTool()]
OPENAI_API_KEY = "sk-proj-AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789AbCdEf01"
