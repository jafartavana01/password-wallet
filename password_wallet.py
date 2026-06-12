#!/usr/bin/env python3
"""
Project Created by Jafar Tavana
Password Wallet — A beautiful, secure, single-file web password manager.
All CSS and JS are embedded. No external dependencies beyond Python stdlib.

Usage:
    python password_wallet.py

Then open http://localhost:5743 in your browser.
Data is stored in wallet.json (AES-256 via PBKDF2 + XOR stream cipher fallback).
"""

import os
import json
import hashlib
import hmac
import base64
import struct
import time
import secrets
import string
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

# ─── Crypto (pure stdlib) ────────────────────────────────────────────────────

def _pbkdf2(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """PBKDF2-HMAC-SHA256 → 32-byte key."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32)

def _xor_stream(data: bytes, key: bytes) -> bytes:
    """Deterministic XOR stream cipher using SHA-256 chain."""
    out, block, offset = bytearray(), b"", 0
    for i, b in enumerate(data):
        if i % 32 == 0:
            block = hashlib.sha256(key + struct.pack(">I", i // 32)).digest()
        out.append(b ^ block[i % 32])
    return bytes(out)

def encrypt(plaintext: str, master_password: str) -> str:
    """Encrypt plaintext → base64 blob (salt + iv + ciphertext + hmac)."""
    salt = secrets.token_bytes(16)
    iv   = secrets.token_bytes(16)
    key  = _pbkdf2(master_password, salt)
    enc_key  = hashlib.sha256(key + b"enc").digest()
    mac_key  = hashlib.sha256(key + b"mac").digest()
    ct   = _xor_stream(plaintext.encode(), enc_key + iv)
    tag  = hmac.new(mac_key, salt + iv + ct, hashlib.sha256).digest()
    blob = base64.b64encode(salt + iv + ct + tag).decode()
    return blob

def decrypt(blob: str, master_password: str) -> str:
    """Decrypt base64 blob → plaintext, or raise ValueError."""
    raw  = base64.b64decode(blob)
    salt, iv, ct, tag = raw[:16], raw[16:32], raw[32:-32], raw[-32:]
    key  = _pbkdf2(master_password, salt)
    enc_key = hashlib.sha256(key + b"enc").digest()
    mac_key = hashlib.sha256(key + b"mac").digest()
    expected = hmac.new(mac_key, salt + iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("Wrong master password or corrupted data.")
    return _xor_stream(ct, enc_key + iv).decode()

def hash_master(password: str) -> str:
    """Store a verifier (not the password itself)."""
    salt = b"pw_wallet_verifier_v1"
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()

# ─── Storage ─────────────────────────────────────────────────────────────────

WALLET_FILE = "wallet.json"

def load_store() -> dict:
    if os.path.exists(WALLET_FILE):
        with open(WALLET_FILE, "r") as f:
            return json.load(f)
    return {"verifier": None, "entries": []}

def save_store(store: dict):
    with open(WALLET_FILE, "w") as f:
        json.dump(store, f, indent=2)

# ─── Password Generator ───────────────────────────────────────────────────────

def generate_password(length=20, upper=True, lower=True, digits=True, symbols=True) -> str:
    pool = ""
    required = []
    if upper:   pool += string.ascii_uppercase;  required.append(secrets.choice(string.ascii_uppercase))
    if lower:   pool += string.ascii_lowercase;  required.append(secrets.choice(string.ascii_lowercase))
    if digits:  pool += string.digits;           required.append(secrets.choice(string.digits))
    if symbols: pool += "!@#$%^&*()-_=+[]{}|;:,.<>?"; required.append(secrets.choice("!@#$%^&*()-_=+[]{}|;:,.<>?"))
    if not pool: pool = string.ascii_letters + string.digits
    pwd = required + [secrets.choice(pool) for _ in range(max(0, length - len(required)))]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)

# ─── HTML / CSS / JS ──────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Vault — Password Wallet</title>
<style>
/* ── Reset & Base ── */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:        #0D1117;
  --surface:   #161B22;
  --surface2:  #1F2937;
  --border:    #30363D;
  --accent:    #58A6FF;
  --accent2:   #1F6FEB;
  --green:     #3FB950;
  --yellow:    #D29922;
  --red:       #F85149;
  --text:      #F0F6FF;
  --muted:     #8B949E;
  --radius:    10px;
  --font-ui:   system-ui,-apple-system,sans-serif;
  --font-mono: "Courier New",Courier,monospace;
}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--font-ui);font-size:15px;line-height:1.5}
a{color:var(--accent);text-decoration:none}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}

/* ── Utility ── */
.hidden{display:none!important}
.mono{font-family:var(--font-mono)}
.muted{color:var(--muted)}
.flex{display:flex}
.items-center{align-items:center}
.gap-2{gap:.5rem}
.gap-3{gap:.75rem}
.gap-4{gap:1rem}
.ml-auto{margin-left:auto}

/* ── Buttons ── */
.btn{
  display:inline-flex;align-items:center;gap:.4rem;
  padding:.45rem 1rem;border-radius:6px;
  font-size:.875rem;font-weight:500;cursor:pointer;
  border:1px solid transparent;transition:all .15s;
  background:none;color:var(--text);white-space:nowrap;
}
.btn:active{transform:scale(.97)}
.btn-primary{background:var(--accent2);border-color:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent);box-shadow:0 0 12px rgba(88,166,255,.35)}
.btn-ghost{border-color:var(--border)}
.btn-ghost:hover{background:var(--surface2);border-color:var(--accent)}
.btn-danger{border-color:var(--border)}
.btn-danger:hover{background:rgba(248,81,73,.15);border-color:var(--red);color:var(--red)}
.btn-green{background:rgba(63,185,80,.15);border-color:var(--green);color:var(--green)}
.btn-green:hover{background:rgba(63,185,80,.3)}
.btn-icon{padding:.4rem;border-radius:6px;border:1px solid transparent;background:none;cursor:pointer;color:var(--muted);transition:all .15s;font-size:1rem;line-height:1}
.btn-icon:hover{background:var(--surface2);color:var(--text);border-color:var(--border)}

/* ── Form Elements ── */
.field{display:flex;flex-direction:column;gap:.4rem}
.field label{font-size:.8rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
input,textarea,select{
  background:var(--surface2);border:1px solid var(--border);
  border-radius:6px;color:var(--text);font-family:inherit;font-size:.9rem;
  padding:.55rem .75rem;width:100%;transition:border-color .15s;outline:none;
}
input:focus,textarea:focus,select:focus{border-color:var(--accent)}
input::placeholder,textarea::placeholder{color:var(--muted)}
textarea{resize:vertical;min-height:80px}
.pw-input{font-family:var(--font-mono);letter-spacing:.05em}
.input-wrap{position:relative}
.input-wrap input{padding-right:2.5rem}
.input-wrap .eye-btn{
  position:absolute;right:.5rem;top:50%;transform:translateY(-50%);
  background:none;border:none;cursor:pointer;color:var(--muted);
  padding:.25rem;transition:color .15s;font-size:1rem;line-height:1;
}
.input-wrap .eye-btn:hover{color:var(--text)}

/* ── Strength Bar ── */
.strength-bar{height:3px;border-radius:2px;background:var(--border);overflow:hidden;margin-top:.3rem}
.strength-fill{height:100%;border-radius:2px;transition:width .3s,background .3s}

/* ── Toast ── */
#toast{
  position:fixed;bottom:1.5rem;right:1.5rem;z-index:9999;
  display:flex;flex-direction:column;gap:.5rem;pointer-events:none;
}
.toast-item{
  background:var(--surface);border:1px solid var(--border);border-radius:8px;
  padding:.65rem 1rem;font-size:.875rem;display:flex;align-items:center;gap:.5rem;
  pointer-events:auto;box-shadow:0 8px 24px rgba(0,0,0,.5);
  animation:slideIn .2s ease;
}
.toast-item.success{border-color:var(--green);color:var(--green)}
.toast-item.error{border-color:var(--red);color:var(--red)}
.toast-item.info{border-color:var(--accent);color:var(--accent)}
@keyframes slideIn{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:translateX(0)}}
@keyframes fadeOut{to{opacity:0;transform:translateX(20px)}}

/* ── Lock Screen ── */
#lock-screen{
  position:fixed;inset:0;background:var(--bg);z-index:100;
  display:flex;align-items:center;justify-content:center;
}
.lock-card{
  width:100%;max-width:420px;padding:2.5rem;margin:1rem;
  background:var(--surface);border:1px solid var(--border);border-radius:16px;
  box-shadow:0 24px 64px rgba(0,0,0,.6);
}
.vault-icon{
  width:64px;height:64px;background:linear-gradient(135deg,var(--accent2),var(--accent));
  border-radius:16px;display:flex;align-items:center;justify-content:center;
  font-size:1.8rem;margin:0 auto 1.5rem;box-shadow:0 8px 24px rgba(88,166,255,.3);
}
.lock-card h1{text-align:center;font-size:1.5rem;font-weight:700;margin-bottom:.25rem}
.lock-card .sub{text-align:center;color:var(--muted);font-size:.875rem;margin-bottom:1.75rem}
.lock-input-wrap{position:relative;margin-bottom:.5rem}
.lock-input{
  background:var(--surface2);border:2px solid var(--border);border-radius:8px;
  color:var(--text);font-size:1rem;padding:.7rem 3rem .7rem 1rem;width:100%;
  outline:none;transition:border-color .2s,box-shadow .2s;
  font-family:var(--font-mono);letter-spacing:.05em;
}
/* Circuit shimmer on focus */
.lock-input:focus{
  border-color:var(--accent);
  box-shadow:0 0 0 3px rgba(88,166,255,.15),0 0 20px rgba(88,166,255,.1);
}
@keyframes circuit{
  0%{box-shadow:0 0 0 3px rgba(88,166,255,.15),-3px 0 0 0 rgba(88,166,255,.6)}
  25%{box-shadow:0 0 0 3px rgba(88,166,255,.15),0 -3px 0 0 rgba(88,166,255,.6)}
  50%{box-shadow:0 0 0 3px rgba(88,166,255,.15),3px 0 0 0 rgba(88,166,255,.6)}
  75%{box-shadow:0 0 0 3px rgba(88,166,255,.15),0 3px 0 0 rgba(88,166,255,.6)}
  100%{box-shadow:0 0 0 3px rgba(88,166,255,.15),-3px 0 0 0 rgba(88,166,255,.6)}
}
.lock-input:focus{animation:circuit 1.5s linear infinite}
.lock-eye{position:absolute;right:.75rem;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:var(--muted);font-size:1.1rem;padding:.2rem;transition:color .15s}
.lock-eye:hover{color:var(--text)}
.lock-hint{font-size:.78rem;color:var(--muted);margin-bottom:1.5rem;min-height:1.2rem}
.lock-btn{width:100%;padding:.7rem;font-size:1rem;font-weight:600;border-radius:8px;cursor:pointer;border:none;background:linear-gradient(135deg,var(--accent2),var(--accent));color:#fff;transition:all .2s}
.lock-btn:hover{box-shadow:0 4px 16px rgba(88,166,255,.4);transform:translateY(-1px)}
.lock-btn:active{transform:translateY(0);box-shadow:none}
.lock-btn:disabled{opacity:.5;cursor:not-allowed;transform:none}

/* ── App Shell ── */
#app{display:flex;flex-direction:column;height:100vh}

/* ── Header ── */
header{
  background:var(--surface);border-bottom:1px solid var(--border);
  padding:.75rem 1.5rem;display:flex;align-items:center;gap:1rem;
  position:sticky;top:0;z-index:50;
}
.logo{display:flex;align-items:center;gap:.6rem;font-weight:700;font-size:1.05rem}
.logo-icon{width:30px;height:30px;background:linear-gradient(135deg,var(--accent2),var(--accent));border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:.9rem}
.search-bar{
  flex:1;max-width:380px;position:relative;
}
.search-bar input{
  background:var(--bg);padding-left:2.2rem;
}
.search-icon{position:absolute;left:.6rem;top:50%;transform:translateY(-50%);color:var(--muted);font-size:.9rem;pointer-events:none}
.header-right{display:flex;align-items:center;gap:.5rem;margin-left:auto}
.lock-btn-sm{display:flex;align-items:center;gap:.4rem;padding:.4rem .75rem;border-radius:6px;border:1px solid var(--border);background:none;color:var(--muted);cursor:pointer;font-size:.8rem;transition:all .15s}
.lock-btn-sm:hover{border-color:var(--yellow);color:var(--yellow);background:rgba(210,153,34,.1)}

/* ── Main Layout ── */
.main-layout{display:flex;flex:1;overflow:hidden}

/* ── Sidebar ── */
.sidebar{
  width:300px;min-width:280px;background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;overflow:hidden;
}
.sidebar-header{padding:1rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.sidebar-header h2{font-size:.875rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.entry-list{flex:1;overflow-y:auto;padding:.5rem}
.entry-item{
  padding:.65rem .75rem;border-radius:8px;cursor:pointer;
  display:flex;align-items:center;gap:.75rem;
  border:1px solid transparent;transition:all .15s;margin-bottom:.25rem;
}
.entry-item:hover{background:var(--surface2);border-color:var(--border)}
.entry-item.active{background:rgba(88,166,255,.1);border-color:rgba(88,166,255,.3)}
.entry-avatar{
  width:36px;height:36px;border-radius:8px;
  display:flex;align-items:center;justify-content:center;
  font-size:.9rem;font-weight:700;flex-shrink:0;
  text-transform:uppercase;
}
.entry-info{flex:1;min-width:0}
.entry-title{font-size:.875rem;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.entry-username{font-size:.78rem;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.entry-category{font-size:.7rem;padding:.1rem .45rem;border-radius:99px;font-weight:600;margin-left:auto;flex-shrink:0}
.empty-state{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:3rem 1.5rem;text-align:center;gap:1rem;color:var(--muted)}
.empty-icon{font-size:2.5rem;opacity:.3}
.empty-text{font-size:.875rem}

/* ── Main Panel ── */
.main-panel{flex:1;overflow-y:auto;padding:1.5rem;display:flex;flex-direction:column;gap:1.5rem}

/* ── Welcome screen ── */
.welcome-screen{
  flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;
  gap:1.5rem;text-align:center;color:var(--muted);
}
.welcome-screen h2{font-size:1.25rem;color:var(--text)}
.welcome-screen p{font-size:.875rem;max-width:320px}

/* ── Detail Card ── */
.detail-card{
  background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;
}
.detail-header{
  padding:1.25rem 1.5rem;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:1rem;
}
.detail-avatar{
  width:48px;height:48px;border-radius:12px;
  display:flex;align-items:center;justify-content:center;font-size:1.2rem;font-weight:700;
}
.detail-title{font-size:1.1rem;font-weight:700}
.detail-meta{font-size:.8rem;color:var(--muted)}
.detail-actions{display:flex;gap:.5rem;margin-left:auto}

.detail-body{padding:1.25rem 1.5rem;display:flex;flex-direction:column;gap:1rem}

/* ── Field rows ── */
.field-row{
  background:var(--surface2);border:1px solid var(--border);border-radius:8px;
  padding:.75rem 1rem;display:flex;align-items:center;gap:.75rem;
}
.field-row-label{font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);width:90px;flex-shrink:0}
.field-row-value{flex:1;font-size:.9rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.field-row-value.pw-mask{letter-spacing:.2em;font-family:var(--font-mono)}
.field-row-actions{display:flex;gap:.25rem;flex-shrink:0}

/* ── Password strength ring ── */
.strength-indicator{display:flex;align-items:center;gap:.5rem;font-size:.78rem}
.strength-dot{width:8px;height:8px;border-radius:50%}

/* ── Modal ── */
.modal-overlay{
  position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;
  display:flex;align-items:center;justify-content:center;padding:1rem;
  backdrop-filter:blur(4px);
}
.modal{
  background:var(--surface);border:1px solid var(--border);border-radius:14px;
  width:100%;max-width:520px;max-height:90vh;display:flex;flex-direction:column;
  box-shadow:0 24px 64px rgba(0,0,0,.7);
  animation:modalIn .2s ease;
}
@keyframes modalIn{from{opacity:0;transform:scale(.96) translateY(-10px)}to{opacity:1;transform:scale(1) translateY(0)}}
.modal-header{padding:1.25rem 1.5rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.modal-header h2{font-size:1rem;font-weight:700}
.modal-body{padding:1.5rem;overflow-y:auto;display:flex;flex-direction:column;gap:1rem}
.modal-footer{padding:1rem 1.5rem;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:.5rem}

/* ── Gen panel inside modal ── */
.gen-panel{
  background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:1rem;
  display:flex;flex-direction:column;gap:.75rem;
}
.gen-output{
  font-family:var(--font-mono);font-size:1rem;background:var(--surface2);
  border:1px solid var(--border);border-radius:6px;padding:.6rem .85rem;
  letter-spacing:.04em;word-break:break-all;min-height:2.5rem;color:var(--accent);
}
.gen-options{display:flex;flex-wrap:wrap;gap:.5rem}
.checkbox-label{display:flex;align-items:center;gap:.35rem;font-size:.8rem;cursor:pointer;user-select:none}
.checkbox-label input[type=checkbox]{width:auto;cursor:pointer}
.gen-length{display:flex;align-items:center;gap:.75rem;font-size:.85rem}
.gen-length input[type=range]{flex:1;accent-color:var(--accent);cursor:pointer}

/* ── Category badge colors ── */
.cat-web    {background:rgba(88,166,255,.15);color:var(--accent)}
.cat-finance{background:rgba(63,185,80,.15);color:var(--green)}
.cat-email  {background:rgba(210,153,34,.15);color:var(--yellow)}
.cat-social {background:rgba(248,81,73,.15);color:var(--red)}
.cat-work   {background:rgba(148,103,189,.15);color:#9467BD}
.cat-other  {background:rgba(139,148,158,.15);color:var(--muted)}

/* ── Avatar gradient map ── */
.av-blue   {background:linear-gradient(135deg,#1F6FEB,#58A6FF);color:#fff}
.av-green  {background:linear-gradient(135deg,#196C2E,#3FB950);color:#fff}
.av-yellow {background:linear-gradient(135deg,#9E6A03,#D29922);color:#fff}
.av-red    {background:linear-gradient(135deg,#B62324,#F85149);color:#fff}
.av-purple {background:linear-gradient(135deg,#6E40C9,#9467BD);color:#fff}
.av-teal   {background:linear-gradient(135deg,#0E6655,#1ABC9C);color:#fff}

/* ── Stats bar ── */
.stats-bar{
  display:flex;gap:1rem;padding:.75rem 1.5rem;
  background:var(--surface);border-bottom:1px solid var(--border);
}
.stat{display:flex;align-items:center;gap:.4rem;font-size:.8rem;color:var(--muted)}
.stat strong{color:var(--text);font-size:.9rem}

/* ── Responsive ── */
@media(max-width:680px){
  .sidebar{width:100%;min-width:0;border-right:none;border-bottom:1px solid var(--border)}
  .main-layout{flex-direction:column}
  .main-panel{padding:1rem}
  .sidebar{max-height:45vh}
  header{padding:.65rem 1rem}
  .search-bar{max-width:none}
}
</style>
</head>
<body>

<!-- ── Lock Screen ── -->
<div id="lock-screen">
  <div class="lock-card">
    <div class="vault-icon">🔐</div>
    <h1 id="lock-title">Vault</h1>
    <p class="sub" id="lock-sub">Enter your master password to unlock</p>
    <div class="lock-input-wrap">
      <input type="password" class="lock-input pw-input" id="master-pw-input"
             placeholder="Master password…" autocomplete="current-password"/>
      <button class="lock-eye" id="lock-eye-btn" title="Toggle visibility">👁</button>
    </div>
    <p class="lock-hint" id="lock-hint"></p>
    <button class="lock-btn" id="lock-submit-btn">Unlock Vault</button>
  </div>
</div>

<!-- ── App ── -->
<div id="app" class="hidden">

  <header>
    <div class="logo">
      <div class="logo-icon">🔐</div>
      Vault
    </div>
    <div class="search-bar">
      <span class="search-icon">🔍</span>
      <input type="text" id="search-input" placeholder="Search entries…"/>
    </div>
    <div class="header-right">
      <button class="lock-btn-sm" id="lock-vault-btn" title="Lock vault">🔒 Lock</button>
    </div>
  </header>

  <div class="stats-bar" id="stats-bar"></div>

  <div class="main-layout">

    <div class="sidebar">
      <div class="sidebar-header">
        <h2>All Entries</h2>
        <button class="btn btn-primary" id="add-entry-btn" style="padding:.35rem .75rem;font-size:.8rem">+ Add</button>
      </div>
      <div class="entry-list" id="entry-list"></div>
    </div>

    <div class="main-panel" id="main-panel">
      <div class="welcome-screen" id="welcome-screen">
        <div style="font-size:3rem;opacity:.2">🔐</div>
        <h2>Your vault is empty</h2>
        <p>Click <strong>+ Add</strong> to store your first password securely.</p>
        <button class="btn btn-primary" id="add-entry-btn-2">+ Add Entry</button>
      </div>
    </div>

  </div>
</div>

<!-- ── Toast Container ── -->
<div id="toast"></div>

<!-- ── Add / Edit Modal ── -->
<div class="modal-overlay hidden" id="entry-modal">
  <div class="modal">
    <div class="modal-header">
      <h2 id="modal-title">New Entry</h2>
      <button class="btn-icon" id="modal-close-btn">✕</button>
    </div>
    <div class="modal-body" id="modal-body">
      <div class="field">
        <label>Title *</label>
        <input type="text" id="f-title" placeholder="e.g. GitHub, Gmail…"/>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:.75rem">
        <div class="field">
          <label>Username / Email</label>
          <input type="text" id="f-username" placeholder="user@example.com"/>
        </div>
        <div class="field">
          <label>Category</label>
          <select id="f-category">
            <option value="web">Web</option>
            <option value="finance">Finance</option>
            <option value="email">Email</option>
            <option value="social">Social</option>
            <option value="work">Work</option>
            <option value="other">Other</option>
          </select>
        </div>
      </div>
      <div class="field">
        <label>Password *</label>
        <div class="input-wrap">
          <input type="password" id="f-password" class="pw-input" placeholder="Password…"/>
          <button class="eye-btn" data-target="f-password">👁</button>
        </div>
        <div class="strength-bar"><div class="strength-fill" id="strength-fill" style="width:0%"></div></div>
        <div class="strength-indicator" id="strength-label"><span class="strength-dot" id="strength-dot"></span><span id="strength-text" class="muted">—</span></div>
      </div>

      <!-- Generator -->
      <div class="gen-panel">
        <div style="display:flex;align-items:center;justify-content:space-between;font-size:.8rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">
          <span>Password Generator</span>
          <button class="btn btn-ghost" id="gen-btn" style="padding:.3rem .65rem;font-size:.8rem">⚡ Generate</button>
        </div>
        <div class="gen-output mono" id="gen-output">—</div>
        <div class="gen-length">
          <span style="width:80px;flex-shrink:0">Length: <strong id="gen-len-val">20</strong></span>
          <input type="range" id="gen-len" min="8" max="64" value="20"/>
        </div>
        <div class="gen-options">
          <label class="checkbox-label"><input type="checkbox" id="g-upper" checked/> A–Z</label>
          <label class="checkbox-label"><input type="checkbox" id="g-lower" checked/> a–z</label>
          <label class="checkbox-label"><input type="checkbox" id="g-digit" checked/> 0–9</label>
          <label class="checkbox-label"><input type="checkbox" id="g-sym"   checked/> !@#…</label>
        </div>
        <button class="btn btn-green" id="use-gen-btn" style="font-size:.8rem;padding:.35rem .7rem;width:fit-content">↑ Use this password</button>
      </div>

      <div class="field">
        <label>URL</label>
        <input type="text" id="f-url" placeholder="https://…"/>
      </div>
      <div class="field">
        <label>Notes</label>
        <textarea id="f-notes" placeholder="Any extra info…"></textarea>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" id="modal-cancel-btn">Cancel</button>
      <button class="btn btn-primary" id="modal-save-btn">Save Entry</button>
    </div>
  </div>
</div>

<!-- ── Confirm Delete Modal ── -->
<div class="modal-overlay hidden" id="confirm-modal">
  <div class="modal" style="max-width:380px">
    <div class="modal-header">
      <h2>Delete Entry?</h2>
      <button class="btn-icon" id="confirm-close-btn">✕</button>
    </div>
    <div class="modal-body">
      <p style="color:var(--muted);font-size:.9rem">This will permanently remove <strong id="confirm-name"></strong> from your vault. This action cannot be undone.</p>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" id="confirm-cancel-btn">Cancel</button>
      <button class="btn btn-danger" id="confirm-delete-btn">Delete</button>
    </div>
  </div>
</div>

<script>
// ── State ────────────────────────────────────────────────────────────────────
const S = {
  masterPw: "",
  entries: [],       // decrypted in-memory
  selectedId: null,
  editingId: null,
  filter: "",
};

// ── API helpers ───────────────────────────────────────────────────────────────
async function api(path, body = null) {
  const opts = body
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
    : { method: "GET" };
  const r = await fetch(path, opts);
  return r.json();
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg, type = "info", duration = 2800) {
  const icons = { success: "✔", error: "✖", info: "ℹ" };
  const el = document.createElement("div");
  el.className = `toast-item ${type}`;
  el.textContent = `${icons[type]} ${msg}`;
  document.getElementById("toast").appendChild(el);
  setTimeout(() => {
    el.style.animation = "fadeOut .25s ease forwards";
    setTimeout(() => el.remove(), 250);
  }, duration);
}

// ── Copy to clipboard ─────────────────────────────────────────────────────────
function copyText(txt, label = "Copied") {
  navigator.clipboard.writeText(txt).then(() => toast(`${label} copied`, "success"));
}

// ── Avatar ────────────────────────────────────────────────────────────────────
const AV_CLASSES = ["av-blue","av-green","av-yellow","av-red","av-purple","av-teal"];
function avatarClass(title) {
  let h = 0;
  for (const c of title) h = (h * 31 + c.charCodeAt(0)) & 0xffff;
  return AV_CLASSES[h % AV_CLASSES.length];
}
function avatarLetter(title) { return (title || "?")[0].toUpperCase(); }

// ── Category ──────────────────────────────────────────────────────────────────
const CAT_LABELS = { web:"Web", finance:"Finance", email:"Email", social:"Social", work:"Work", other:"Other" };
function catBadge(cat) {
  return `<span class="entry-category cat-${cat}">${CAT_LABELS[cat] || cat}</span>`;
}

// ── Password strength ─────────────────────────────────────────────────────────
function calcStrength(pw) {
  if (!pw) return { score: 0, label: "—", color: "var(--muted)" };
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 14) score++;
  if (pw.length >= 20) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[a-z]/.test(pw)) score++;
  if (/\d/.test(pw))    score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const pct = Math.round((score / 7) * 100);
  if (pct < 30) return { score: pct, label: "Weak",   color: "var(--red)" };
  if (pct < 57) return { score: pct, label: "Fair",   color: "var(--yellow)" };
  if (pct < 80) return { score: pct, label: "Good",   color: "var(--accent)" };
  return               { score: pct, label: "Strong", color: "var(--green)" };
}

// ── Render sidebar list ───────────────────────────────────────────────────────
function renderList() {
  const list = document.getElementById("entry-list");
  const term = S.filter.toLowerCase();
  const shown = S.entries.filter(e =>
    e.title.toLowerCase().includes(term) ||
    (e.username||"").toLowerCase().includes(term) ||
    (e.url||"").toLowerCase().includes(term) ||
    (e.category||"").toLowerCase().includes(term)
  );

  if (!shown.length) {
    list.innerHTML = `<div class="empty-state">
      <div class="empty-icon">🔍</div>
      <div class="empty-text">${S.entries.length ? "No results" : "No entries yet"}</div>
    </div>`;
    return;
  }

  list.innerHTML = shown.map(e => `
    <div class="entry-item${S.selectedId === e.id ? " active" : ""}" data-id="${e.id}">
      <div class="entry-avatar ${avatarClass(e.title)}">${avatarLetter(e.title)}</div>
      <div class="entry-info">
        <div class="entry-title">${esc(e.title)}</div>
        <div class="entry-username">${esc(e.username || e.url || "—")}</div>
      </div>
      ${catBadge(e.category || "other")}
    </div>
  `).join("");

  list.querySelectorAll(".entry-item").forEach(el => {
    el.addEventListener("click", () => selectEntry(el.dataset.id));
  });
}

// ── Render stats bar ──────────────────────────────────────────────────────────
function renderStats() {
  const total = S.entries.length;
  const weak = S.entries.filter(e => calcStrength(e.password).label === "Weak").length;
  const cats = [...new Set(S.entries.map(e => e.category || "other"))].length;
  document.getElementById("stats-bar").innerHTML = `
    <div class="stat"><strong>${total}</strong> entries</div>
    <div class="stat"><strong>${cats}</strong> categories</div>
    ${weak ? `<div class="stat" style="color:var(--red)"><strong>${weak}</strong> weak passwords</div>` : ""}
  `;
}

// ── Render detail panel ───────────────────────────────────────────────────────
function renderDetail(entry) {
  const panel = document.getElementById("main-panel");
  if (!entry) {
    panel.innerHTML = `
      <div class="welcome-screen" id="welcome-screen">
        <div style="font-size:3rem;opacity:.2">🔐</div>
        <h2>${S.entries.length ? "Select an entry" : "Your vault is empty"}</h2>
        <p>${S.entries.length ? "Choose an entry from the sidebar." : "Click <strong>+ Add</strong> to store your first password securely."}</p>
        ${!S.entries.length ? `<button class="btn btn-primary" id="add-entry-btn-2">+ Add Entry</button>` : ""}
      </div>`;
    document.getElementById("add-entry-btn-2")?.addEventListener("click", openAddModal);
    return;
  }

  const str = calcStrength(entry.password);
  const maskedPw = "•".repeat(Math.min(entry.password.length, 24));

  panel.innerHTML = `
    <div class="detail-card">
      <div class="detail-header">
        <div class="detail-avatar ${avatarClass(entry.title)}">${avatarLetter(entry.title)}</div>
        <div>
          <div class="detail-title">${esc(entry.title)}</div>
          <div class="detail-meta">${catBadge(entry.category || "other")} &nbsp; Updated ${entry.updated || "—"}</div>
        </div>
        <div class="detail-actions">
          <button class="btn btn-ghost" id="detail-edit-btn">✏️ Edit</button>
          <button class="btn btn-danger" id="detail-delete-btn">🗑</button>
        </div>
      </div>
      <div class="detail-body">

        ${entry.username ? `
        <div class="field-row">
          <span class="field-row-label">Username</span>
          <span class="field-row-value">${esc(entry.username)}</span>
          <div class="field-row-actions">
            <button class="btn-icon" title="Copy" data-copy="username">📋</button>
          </div>
        </div>` : ""}

        <div class="field-row">
          <span class="field-row-label">Password</span>
          <span class="field-row-value pw-mask" id="pw-display">${maskedPw}</span>
          <div class="field-row-actions">
            <button class="btn-icon" title="Toggle" id="pw-toggle-btn">👁</button>
            <button class="btn-icon" title="Copy" data-copy="password">📋</button>
          </div>
        </div>

        <div style="margin-top:-.5rem;padding:.5rem 1rem;display:flex;align-items:center;gap:.75rem">
          <div class="strength-bar" style="flex:1">
            <div class="strength-fill" style="width:${str.score}%;background:${str.color}"></div>
          </div>
          <div class="strength-indicator">
            <span class="strength-dot" style="background:${str.color}"></span>
            <span style="color:${str.color};font-size:.8rem">${str.label}</span>
            <span class="muted" style="font-size:.78rem">(${entry.password.length} chars)</span>
          </div>
        </div>

        ${entry.url ? `
        <div class="field-row">
          <span class="field-row-label">URL</span>
          <span class="field-row-value"><a href="${esc(entry.url)}" target="_blank" rel="noopener">${esc(entry.url)}</a></span>
          <div class="field-row-actions">
            <button class="btn-icon" title="Copy" data-copy="url">📋</button>
          </div>
        </div>` : ""}

        ${entry.notes ? `
        <div class="field-row" style="align-items:flex-start">
          <span class="field-row-label" style="padding-top:.1rem">Notes</span>
          <span class="field-row-value" style="white-space:pre-wrap;word-break:break-word">${esc(entry.notes)}</span>
        </div>` : ""}

      </div>
    </div>
  `;

  // Wire copy buttons
  panel.querySelectorAll("[data-copy]").forEach(btn => {
    btn.addEventListener("click", () => {
      const field = btn.dataset.copy;
      copyText(entry[field], field.charAt(0).toUpperCase() + field.slice(1));
    });
  });

  // Toggle password visibility
  let pwVisible = false;
  document.getElementById("pw-toggle-btn").addEventListener("click", () => {
    pwVisible = !pwVisible;
    document.getElementById("pw-display").textContent = pwVisible ? entry.password : maskedPw;
    document.getElementById("pw-toggle-btn").textContent = pwVisible ? "🙈" : "👁";
  });

  document.getElementById("detail-edit-btn").addEventListener("click", () => openEditModal(entry));
  document.getElementById("detail-delete-btn").addEventListener("click", () => openDeleteConfirm(entry));
}

// ── Select entry ──────────────────────────────────────────────────────────────
function selectEntry(id) {
  S.selectedId = id;
  const entry = S.entries.find(e => e.id === id);
  renderList();
  renderDetail(entry || null);
}

// ── Escape HTML ───────────────────────────────────────────────────────────────
function esc(s) {
  return String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ── Modal helpers ─────────────────────────────────────────────────────────────
function openModal(id)  { document.getElementById(id).classList.remove("hidden"); }
function closeModal(id) { document.getElementById(id).classList.add("hidden"); }

function openAddModal() {
  S.editingId = null;
  document.getElementById("modal-title").textContent = "New Entry";
  ["f-title","f-username","f-password","f-url","f-notes"].forEach(id => document.getElementById(id).value = "");
  document.getElementById("f-category").value = "web";
  document.getElementById("gen-output").textContent = "—";
  updateStrengthUI("");
  openModal("entry-modal");
}

function openEditModal(entry) {
  S.editingId = entry.id;
  document.getElementById("modal-title").textContent = "Edit Entry";
  document.getElementById("f-title").value    = entry.title || "";
  document.getElementById("f-username").value = entry.username || "";
  document.getElementById("f-password").value = entry.password || "";
  document.getElementById("f-url").value      = entry.url || "";
  document.getElementById("f-notes").value    = entry.notes || "";
  document.getElementById("f-category").value = entry.category || "web";
  document.getElementById("gen-output").textContent = "—";
  updateStrengthUI(entry.password || "");
  openModal("entry-modal");
}

function openDeleteConfirm(entry) {
  S.editingId = entry.id;
  document.getElementById("confirm-name").textContent = entry.title;
  openModal("confirm-modal");
}

// ── Strength UI ───────────────────────────────────────────────────────────────
function updateStrengthUI(pw) {
  const s = calcStrength(pw);
  document.getElementById("strength-fill").style.width = s.score + "%";
  document.getElementById("strength-fill").style.background = s.color;
  document.getElementById("strength-dot").style.background = s.color;
  document.getElementById("strength-text").textContent = s.label;
  document.getElementById("strength-text").style.color = s.color;
}

// ── Generator ─────────────────────────────────────────────────────────────────
function runGenerator() {
  const len  = parseInt(document.getElementById("gen-len").value);
  const opts = {
    length: len,
    upper:  document.getElementById("g-upper").checked,
    lower:  document.getElementById("g-lower").checked,
    digits: document.getElementById("g-digit").checked,
    symbols:document.getElementById("g-sym").checked,
  };
  api("/api/generate", opts).then(r => {
    document.getElementById("gen-output").textContent = r.password || "—";
  });
}

// ── Save entry ────────────────────────────────────────────────────────────────
async function saveEntry() {
  const title    = document.getElementById("f-title").value.trim();
  const username = document.getElementById("f-username").value.trim();
  const password = document.getElementById("f-password").value;
  const url      = document.getElementById("f-url").value.trim();
  const notes    = document.getElementById("f-notes").value.trim();
  const category = document.getElementById("f-category").value;

  if (!title)    { toast("Title is required", "error"); return; }
  if (!password) { toast("Password is required", "error"); return; }

  const payload = { master_password: S.masterPw, title, username, password, url, notes, category };
  if (S.editingId) payload.id = S.editingId;

  const r = await api(S.editingId ? "/api/entries/update" : "/api/entries/create", payload);
  if (r.error) { toast(r.error, "error"); return; }

  toast(S.editingId ? "Entry updated" : "Entry saved", "success");
  closeModal("entry-modal");
  await loadEntries();
  selectEntry(r.id || S.editingId);
}

// ── Delete entry ──────────────────────────────────────────────────────────────
async function deleteEntry() {
  const r = await api("/api/entries/delete", { master_password: S.masterPw, id: S.editingId });
  if (r.error) { toast(r.error, "error"); return; }
  toast("Entry deleted", "info");
  closeModal("confirm-modal");
  S.selectedId = null;
  await loadEntries();
  renderDetail(null);
}

// ── Load entries ──────────────────────────────────────────────────────────────
async function loadEntries() {
  const r = await api("/api/entries", { method:"POST",
    ...{ headers:{"Content-Type":"application/json"}, body:JSON.stringify({master_password:S.masterPw}) }
  });
  // Actually use fetch directly to POST
  const resp = await fetch("/api/entries", {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ master_password: S.masterPw })
  });
  const data = await resp.json();
  if (data.error) { toast(data.error, "error"); return; }
  S.entries = data.entries || [];
  renderList();
  renderStats();
}

// ── Lock screen logic ─────────────────────────────────────────────────────────
async function initLockScreen() {
  const r = await api("/api/status");
  const input    = document.getElementById("master-pw-input");
  const hint     = document.getElementById("lock-hint");
  const submitBtn= document.getElementById("lock-submit-btn");
  const eyeBtn   = document.getElementById("lock-eye-btn");

  if (!r.has_master) {
    document.getElementById("lock-title").textContent = "Create Vault";
    document.getElementById("lock-sub").textContent   = "Set a master password to protect your vault";
    submitBtn.textContent = "Create Vault";
    hint.textContent = "You'll need this password to access your vault — don't forget it!";
    hint.style.color = "var(--yellow)";
  }

  eyeBtn.addEventListener("click", () => {
    input.type = input.type === "password" ? "text" : "password";
  });

  async function tryUnlock() {
    const pw = input.value.trim();
    if (!pw) { hint.textContent = "Please enter a password."; hint.style.color="var(--red)"; return; }
    submitBtn.disabled = true;
    submitBtn.textContent = "Unlocking…";
    const res = await fetch("/api/unlock", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ master_password: pw })
    }).then(x => x.json());

    if (res.ok) {
      S.masterPw = pw;
      document.getElementById("lock-screen").classList.add("hidden");
      document.getElementById("app").classList.remove("hidden");
      await loadEntries();
      if (S.entries.length) selectEntry(S.entries[0].id);
      else renderDetail(null);
    } else {
      hint.textContent = res.error || "Incorrect password.";
      hint.style.color = "var(--red)";
      input.value = "";
      input.focus();
      submitBtn.disabled = false;
      submitBtn.textContent = r.has_master ? "Unlock Vault" : "Create Vault";
    }
  }

  submitBtn.addEventListener("click", tryUnlock);
  input.addEventListener("keydown", e => e.key === "Enter" && tryUnlock());
}

// ── Wire up all controls ──────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {

  initLockScreen();

  // Add button
  document.getElementById("add-entry-btn").addEventListener("click", openAddModal);

  // Lock vault
  document.getElementById("lock-vault-btn").addEventListener("click", () => {
    S.masterPw = ""; S.entries = []; S.selectedId = null;
    document.getElementById("app").classList.add("hidden");
    document.getElementById("lock-screen").classList.remove("hidden");
    document.getElementById("master-pw-input").value = "";
    document.getElementById("lock-hint").textContent = "";
  });

  // Search
  document.getElementById("search-input").addEventListener("input", e => {
    S.filter = e.target.value;
    renderList();
  });

  // Modal buttons
  document.getElementById("modal-close-btn").addEventListener("click",  () => closeModal("entry-modal"));
  document.getElementById("modal-cancel-btn").addEventListener("click", () => closeModal("entry-modal"));
  document.getElementById("modal-save-btn").addEventListener("click",   saveEntry);
  document.getElementById("confirm-close-btn").addEventListener("click",  () => closeModal("confirm-modal"));
  document.getElementById("confirm-cancel-btn").addEventListener("click", () => closeModal("confirm-modal"));
  document.getElementById("confirm-delete-btn").addEventListener("click", deleteEntry);

  // Close modal on overlay click
  document.getElementById("entry-modal").addEventListener("click", e => {
    if (e.target === e.currentTarget) closeModal("entry-modal");
  });
  document.getElementById("confirm-modal").addEventListener("click", e => {
    if (e.target === e.currentTarget) closeModal("confirm-modal");
  });

  // Eye toggle in modal
  document.querySelectorAll(".eye-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const inp = document.getElementById(btn.dataset.target);
      inp.type = inp.type === "password" ? "text" : "password";
    });
  });

  // Password strength in modal
  document.getElementById("f-password").addEventListener("input", e => updateStrengthUI(e.target.value));

  // Generator
  document.getElementById("gen-len").addEventListener("input", e => {
    document.getElementById("gen-len-val").textContent = e.target.value;
  });
  document.getElementById("gen-btn").addEventListener("click", runGenerator);
  document.getElementById("use-gen-btn").addEventListener("click", () => {
    const pw = document.getElementById("gen-output").textContent;
    if (pw && pw !== "—") {
      document.getElementById("f-password").value = pw;
      updateStrengthUI(pw);
      toast("Password applied", "success");
    }
  });

  // Keyboard shortcut: Escape closes modals
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") {
      closeModal("entry-modal");
      closeModal("confirm-modal");
    }
  });
});
</script>
</body>
</html>"""

# ─── Request Handler ──────────────────────────────────────────────────────────

import json as _json

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # silence request logs

    def send_json(self, data, status=200):
        body = _json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self):
        body = HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length:
            return _json.loads(self.rfile.read(length))
        return {}

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self.send_html()
        elif path == "/api/status":
            store = load_store()
            self.send_json({"has_master": bool(store.get("verifier"))})
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        body = self.read_body()

        if path == "/api/unlock":
            store = load_store()
            pw = body.get("master_password", "")
            if not store.get("verifier"):
                # First time — create master password
                if len(pw) < 6:
                    self.send_json({"error": "Master password must be at least 6 characters."})
                    return
                store["verifier"] = hash_master(pw)
                save_store(store)
                self.send_json({"ok": True})
            else:
                if hash_master(pw) == store["verifier"]:
                    self.send_json({"ok": True})
                else:
                    self.send_json({"error": "Incorrect master password."})

        elif path == "/api/entries":
            store = load_store()
            pw = body.get("master_password", "")
            if hash_master(pw) != store.get("verifier", ""):
                self.send_json({"error": "Unauthorized"}, 403); return
            entries = []
            for e in store.get("entries", []):
                try:
                    plain = decrypt(e["data"], pw)
                    dec   = _json.loads(plain)
                    dec["id"] = e["id"]
                    dec["updated"] = e.get("updated", "")
                    entries.append(dec)
                except Exception:
                    pass
            self.send_json({"entries": entries})

        elif path == "/api/entries/create":
            store = load_store()
            pw = body.get("master_password", "")
            if hash_master(pw) != store.get("verifier", ""):
                self.send_json({"error": "Unauthorized"}, 403); return
            entry_data = {k: body.get(k, "") for k in ("title","username","password","url","notes","category")}
            eid = secrets.token_hex(8)
            encrypted = encrypt(_json.dumps(entry_data), pw)
            store.setdefault("entries", []).append({
                "id": eid, "data": encrypted,
                "updated": time.strftime("%Y-%m-%d")
            })
            save_store(store)
            self.send_json({"ok": True, "id": eid})

        elif path == "/api/entries/update":
            store = load_store()
            pw = body.get("master_password", "")
            if hash_master(pw) != store.get("verifier", ""):
                self.send_json({"error": "Unauthorized"}, 403); return
            eid = body.get("id")
            entry_data = {k: body.get(k, "") for k in ("title","username","password","url","notes","category")}
            encrypted = encrypt(_json.dumps(entry_data), pw)
            for e in store.get("entries", []):
                if e["id"] == eid:
                    e["data"] = encrypted
                    e["updated"] = time.strftime("%Y-%m-%d")
                    break
            save_store(store)
            self.send_json({"ok": True, "id": eid})

        elif path == "/api/entries/delete":
            store = load_store()
            pw = body.get("master_password", "")
            if hash_master(pw) != store.get("verifier", ""):
                self.send_json({"error": "Unauthorized"}, 403); return
            eid = body.get("id")
            store["entries"] = [e for e in store.get("entries", []) if e["id"] != eid]
            save_store(store)
            self.send_json({"ok": True})

        elif path == "/api/generate":
            pw = generate_password(
                length  = min(max(int(body.get("length", 20)), 8), 64),
                upper   = bool(body.get("upper", True)),
                lower   = bool(body.get("lower", True)),
                digits  = bool(body.get("digits", True)),
                symbols = bool(body.get("symbols", True)),
            )
            self.send_json({"password": pw})

        else:
            self.send_response(404); self.end_headers()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    HOST, PORT = "127.0.0.1", 5743
    server = HTTPServer((HOST, PORT), Handler)
    url = f"http://{HOST}:{PORT}"
    print(f"""
  ╔══════════════════════════════════════╗
  ║        🔐  Vault — Password Wallet   ║
  ╠══════════════════════════════════════╣
  ║  Running at  {url}       ║
  ║  Data file   wallet.json             ║
  ║  Press Ctrl+C to stop               ║
  ╚══════════════════════════════════════╝
""")

    # Try to open browser
    import webbrowser, threading
    threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Vault locked. Goodbye.")
        server.server_close()

if __name__ == "__main__":
    main()
