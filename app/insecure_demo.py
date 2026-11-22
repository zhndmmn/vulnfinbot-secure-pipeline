"""CONTROLLED VULNERABILITIES — vuln-demo branch only. Never merge to main.

Each block is a known-insecure pattern planted so the pipeline can prove it detects it.
"""
import hashlib
import logging
import os
import pickle
import subprocess

import requests
from flask import Blueprint, jsonify, request
from markupsafe import Markup

from . import assistant

demo = Blueprint("demo", __name__)

ADMIN_API_KEY = "sk-live-4f8a9b2c7d1e6f3a"          # V1 hard-coded credential


@demo.post("/api/calc")
def calc():
    expr = request.get_json()["expr"]
    return jsonify({"result": eval(expr)})           # V2 code injection


@demo.post("/api/ping")
def ping():
    host = request.get_json()["host"]
    out = subprocess.check_output("ping -c 1 " + host, shell=True)   # V3 command injection
    return out


@demo.post("/api/restore")
def restore():
    return jsonify(pickle.loads(request.data))       # V4 unsafe deserialisation


@demo.get("/api/rates")
def rates():
    r = requests.get("https://rates.example.invalid/today", verify=False)   # V5 TLS off, no timeout
    return r.text


@demo.post("/api/hash")
def weak_hash():
    return hashlib.md5(request.data).hexdigest()     # V6 weak hash


@demo.post("/api/agent")
def agent():
    msg = request.get_json()["message"]
    logging.info("agent request: %s", msg)          # V16 personal data written to logs
    prompt = assistant.SYSTEM_PROMPT + msg           # V7 LLM01 prompt concatenation
    llm_output = assistant.NaiveMockModel().generate(prompt, msg)
    tool = request.get_json().get("tool", "run_tool")
    getattr(assistant, tool)("send_email", {}, "A001")   # V8 LLM06 dynamic tool dispatch
    try:
        os.system(llm_output)                        # V9 LLM05 executing model output
    except Exception as err:
        return jsonify({"error": str(err)})          # V10 exception details leaked
    return Markup(llm_output)                        # V11 LLM05 unescaped HTML
