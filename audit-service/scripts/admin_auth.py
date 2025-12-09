#!/usr/bin/env python3
"""
Admin Authentication Helper

This script provides utility functions for JWT authentication.
Use it to:
1. Login and get JWT token
2. Test admin endpoints with JWT
3. Manage admin users

Usage:
    python admin_auth.py login
    python admin_auth.py test-jwt
    python admin_auth.py create-user <username> <password>
"""

import os
import sys
import json
import requests
import socket

API_BASE = "http://localhost"

# Burp Suite proxy settings
BURP_PROXY_HOST = "127.0.0.1"
BURP_PROXY_PORT = 8080
BURP_PROXIES = None


def check_burp_proxy() -> bool:
    """Check if Burp Suite proxy is running."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((BURP_PROXY_HOST, BURP_PROXY_PORT))
        sock.close()
        return result == 0
    except Exception:
        return False


def setup_proxy():
    """Setup proxy if Burp Suite is detected."""
    global BURP_PROXIES
    if check_burp_proxy():
        BURP_PROXIES = {
            "http": f"http://{BURP_PROXY_HOST}:{BURP_PROXY_PORT}",
            "https": f"http://{BURP_PROXY_HOST}:{BURP_PROXY_PORT}"
        }
        print(f"🔍 Burp Suite detected on port {BURP_PROXY_PORT}")
        return True
    return False


def make_request(method: str, url: str, **kwargs) -> requests.Response:
    """Make HTTP request with optional proxy."""
    kwargs.setdefault('timeout', 10)
    if BURP_PROXIES:
        kwargs['proxies'] = BURP_PROXIES
        kwargs['verify'] = False
    
    return getattr(requests, method.lower())(url, **kwargs)


def login(username: str = None, password: str = None) -> dict:
    """
    Login and get JWT token.
    
    Returns:
        dict with access_token, token_type, expires_in
    """
    if not username:
        username = input("Username: ")
    if not password:
        password = input("Password: ")
    
    print(f"\n🔐 Logging in as '{username}'...")
    
    resp = make_request(
        'POST',
        f"{API_BASE}/v1/auth/login",
        json={"username": username, "password": password}
    )
    
    if resp.status_code == 200:
        data = resp.json()
        print(f"✅ Login successful!")
        print(f"\n📝 Token Info:")
        print(f"   Type: {data['token_type']}")
        print(f"   Expires in: {data['expires_in']} seconds")
        print(f"\n🔑 Access Token:")
        print(f"   {data['access_token'][:50]}...")
        print(f"\n💡 Usage:")
        print(f'   curl -H "Authorization: Bearer {data["access_token"][:30]}..." ...')
        
        # Save token to file for convenience
        with open("admin_token.txt", "w") as f:
            f.write(data['access_token'])
        print(f"\n📄 Token saved to admin_token.txt")
        
        return data
    else:
        print(f"❌ Login failed: {resp.status_code}")
        print(f"   {resp.text}")
        return None


def test_jwt(token: str = None):
    """Test JWT authentication with admin endpoint."""
    if not token:
        try:
            with open("admin_token.txt", "r") as f:
                token = f.read().strip()
            print(f"📄 Using token from admin_token.txt")
        except FileNotFoundError:
            print("❌ No token found. Run 'login' first.")
            return
    
    print(f"\n🧪 Testing JWT authentication...")
    
    # Test /auth/me endpoint
    print(f"\n1️⃣ GET /v1/auth/me")
    resp = make_request(
        'GET',
        f"{API_BASE}/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    print(f"   Status: {resp.status_code}")
    if resp.status_code == 200:
        print(f"   User: {resp.json()}")
    else:
        print(f"   Error: {resp.text}")
    
    # Test admin endpoint
    print(f"\n2️⃣ GET /v1/admin/keys/pending")
    resp = make_request(
        'GET',
        f"{API_BASE}/v1/admin/keys/pending",
        headers={"Authorization": f"Bearer {token}"}
    )
    print(f"   Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        print(f"   Pending keys: {data['pending_count']}")
    else:
        print(f"   Error: {resp.text}")
    
    # Test list keys
    print(f"\n3️⃣ GET /v1/admin/keys")
    resp = make_request(
        'GET',
        f"{API_BASE}/v1/admin/keys",
        headers={"Authorization": f"Bearer {token}"}
    )
    print(f"   Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        print(f"   Total keys: {data.get('total', 'N/A')}")


def test_legacy_token():
    """Test legacy X-Admin-Token authentication."""
    token = "my-super-secret-admin-token-2025"
    
    print(f"\n🧪 Testing legacy X-Admin-Token authentication...")
    
    resp = make_request(
        'GET',
        f"{API_BASE}/v1/admin/keys/pending",
        headers={"X-Admin-Token": token}
    )
    
    print(f"   Status: {resp.status_code}")
    if resp.status_code == 200:
        print(f"   ✅ Legacy token still works (backward compatible)")
        data = resp.json()
        print(f"   Pending keys: {data['pending_count']}")
    else:
        print(f"   ❌ Error: {resp.text}")


def create_user(username: str, password: str, email: str = None, role: str = "admin"):
    """Create a new admin user."""
    # First login to get token
    try:
        with open("admin_token.txt", "r") as f:
            token = f.read().strip()
    except FileNotFoundError:
        print("❌ No token found. Run 'login' first.")
        return
    
    print(f"\n👤 Creating user '{username}'...")
    
    resp = make_request(
        'POST',
        f"{API_BASE}/v1/auth/users",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "username": username,
            "password": password,
            "email": email,
            "role": role
        }
    )
    
    if resp.status_code == 200:
        user = resp.json()
        print(f"✅ User created!")
        print(f"   ID: {user['id']}")
        print(f"   Username: {user['username']}")
        print(f"   Role: {user['role']}")
    else:
        print(f"❌ Failed: {resp.status_code}")
        print(f"   {resp.text}")


def list_users():
    """List all admin users."""
    try:
        with open("admin_token.txt", "r") as f:
            token = f.read().strip()
    except FileNotFoundError:
        print("❌ No token found. Run 'login' first.")
        return
    
    print(f"\n👥 Admin Users:")
    
    resp = make_request(
        'GET',
        f"{API_BASE}/v1/auth/users",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    if resp.status_code == 200:
        users = resp.json()
        for u in users:
            status = "✅" if u['is_active'] else "❌"
            print(f"   {status} {u['id']}: {u['username']} ({u['role']})")
    else:
        print(f"❌ Failed: {resp.text}")


def main():
    setup_proxy()
    
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nCommands:")
        print("  login                    - Login and get JWT token")
        print("  test-jwt                 - Test JWT authentication")
        print("  test-legacy              - Test legacy X-Admin-Token")
        print("  create-user <u> <p>      - Create new admin user")
        print("  list-users               - List all admin users")
        return
    
    cmd = sys.argv[1].lower()
    
    if cmd == "login":
        username = sys.argv[2] if len(sys.argv) > 2 else None
        password = sys.argv[3] if len(sys.argv) > 3 else None
        login(username, password)
    
    elif cmd == "test-jwt":
        token = sys.argv[2] if len(sys.argv) > 2 else None
        test_jwt(token)
    
    elif cmd == "test-legacy":
        test_legacy_token()
    
    elif cmd == "create-user":
        if len(sys.argv) < 4:
            print("Usage: admin_auth.py create-user <username> <password> [email] [role]")
            return
        username = sys.argv[2]
        password = sys.argv[3]
        email = sys.argv[4] if len(sys.argv) > 4 else None
        role = sys.argv[5] if len(sys.argv) > 5 else "admin"
        create_user(username, password, email, role)
    
    elif cmd == "list-users":
        list_users()
    
    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
