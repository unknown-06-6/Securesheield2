import json
import requests

BASE = "http://localhost:5000"
SEP = "-" * 50


def show(title, resp):
    print(f"\n{SEP}\n{title}\n{SEP}")
    try:
        print(json.dumps(resp.json(), indent=2))
    except Exception:
        print(resp.text)


show("TASK 1 - Register user1 (user role)",
     requests.post(f"{BASE}/register", json={"username": "user1", "password": "user1pass", "role": "user"}))

show("TASK 1 - Register admin1 (admin role)",
     requests.post(f"{BASE}/register", json={"username": "admin1", "password": "admin1pass", "role": "admin"}))

user_resp = requests.post(f"{BASE}/login", json={"username": "user1", "password": "user1pass"})
show("TASK 2 - Login as user1", user_resp)
user_token = user_resp.json().get("token", "")

admin_resp = requests.post(f"{BASE}/login", json={"username": "admin1", "password": "admin1pass"})
show("TASK 2 - Login as admin1", admin_resp)
admin_token = admin_resp.json().get("token", "")

show("TASK 3+4 - GET /profile as user1",
     requests.get(f"{BASE}/profile", headers={"Authorization": f"Bearer {user_token}"}))

show("TASK 3+4 - GET /profile as admin1",
     requests.get(f"{BASE}/profile", headers={"Authorization": f"Bearer {admin_token}"}))

show("TASK 4 - user1 tries DELETE /user/1 -> 403 Forbidden",
     requests.delete(f"{BASE}/user/1", headers={"Authorization": f"Bearer {user_token}"}))

requests.post(f"{BASE}/register", json={"username": "throwaway", "password": "pw", "role": "user"})
users = requests.get(f"{BASE}/users", headers={"Authorization": f"Bearer {admin_token}"}).json().get("users", [])
throwaway = next((u for u in users if u["username"] == "throwaway"), None)
if throwaway:
    show("TASK 4 - admin1 deletes throwaway user -> 200 OK",
         requests.delete(f"{BASE}/user/{throwaway['id']}", headers={"Authorization": f"Bearer {admin_token}"}))

show("TASK 5 - Logout user1 (revoke token)",
     requests.post(f"{BASE}/logout", headers={"Authorization": f"Bearer {user_token}"}))

show("TASK 5 - Use revoked token -> 401",
     requests.get(f"{BASE}/profile", headers={"Authorization": f"Bearer {user_token}"}))

fake_token = user_token[:-10] + "AAAAAAAAAA"
show("TASK 6 - Tampered token -> 401",
     requests.get(f"{BASE}/profile", headers={"Authorization": f"Bearer {fake_token}"}))

print(f"\n{SEP}\nChecking security.log for 403 entries\n{SEP}")
try:
    with open("security.log") as f:
        lines = f.readlines()
    print(f"{len(lines)} entry/entries:")
    for line in lines[-5:]:
        print(" ", line.strip())
except FileNotFoundError:
    print("security.log not found")

print(f"\n{SEP}\nALL TESTS COMPLETE\n{SEP}\n")
