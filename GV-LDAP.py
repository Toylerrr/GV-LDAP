import ldap
import requests
import json

# LDAP server configuration
LDAP_SERVER = 'ldap://your-ldap-server'
LDAP_BASE_DN = 'dc=example,dc=com'
LDAP_USER_DN = 'ou=users,' + LDAP_BASE_DN
LDAP_ADMIN_USER = 'cn=admin,' + LDAP_BASE_DN
LDAP_ADMIN_PASSWORD = 'your_admin_password'

# GameVault API configuration
GAMEVAULT_API_URL = 'https://gamevault.example.com/api'
GAMEVAULT_API_USER = 'your_api_user'
GAMEVAULT_API_PASSWORD = 'your_api_password'

# Initialize LDAP connection
def init_ldap_connection():
    ldap_conn = ldap.initialize(LDAP_SERVER)
    ldap_conn.simple_bind_s(LDAP_ADMIN_USER, LDAP_ADMIN_PASSWORD)
    return ldap_conn

# Get all LDAP users
def get_ldap_users(ldap_conn):
    search_filter = "(objectClass=inetOrgPerson)"
    result = ldap_conn.search_s(LDAP_USER_DN, ldap.SCOPE_SUBTREE, search_filter)
    users = []
    for dn, entry in result:
        users.append(entry)
    return users

# Authenticate against GameVault API
def authenticate_gamevault():
    response = requests.get(GAMEVAULT_API_URL + '/users/me', auth=(GAMEVAULT_API_USER, GAMEVAULT_API_PASSWORD))
    if response.status_code == 200:
        return True
    else:
        raise Exception("Failed to authenticate with GameVault")

# Get all users from GameVault
def get_gamevault_users():
    response = requests.get(GAMEVAULT_API_URL + '/users', auth=(GAMEVAULT_API_USER, GAMEVAULT_API_PASSWORD))
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception("Failed to retrieve users from GameVault")

# Create or update a user in GameVault
def create_or_update_gamevault_user(user):
    gamevault_user = {
        'username': user['uid'][0].decode('utf-8'),
        'email': user['mail'][0].decode('utf-8'),
        'password': 'default_password'  # Ensure to set a proper password
    }
    
    response = requests.post(GAMEVAULT_API_URL + '/users/register', json=gamevault_user, auth=(GAMEVAULT_API_USER, GAMEVAULT_API_PASSWORD))
    if response.status_code == 200:
        print(f"User {gamevault_user['username']} created/updated in GameVault")
    else:
        print(f"Failed to create/update user {gamevault_user['username']} in GameVault")

# Delete a user from GameVault
def delete_gamevault_user(username):
    response = requests.delete(f"{GAMEVAULT_API_URL}/users/{username}", auth=(GAMEVAULT_API_USER, GAMEVAULT_API_PASSWORD))
    if response.status_code == 200:
        print(f"User {username} deleted from GameVault")
    else:
        print(f"Failed to delete user {username} from GameVault")

# Main function
def main():
    try:
        # Initialize connections
        ldap_conn = init_ldap_connection()
        authenticate_gamevault()

        # Get LDAP users
        ldap_users = get_ldap_users(ldap_conn)
        ldap_usernames = {user['uid'][0].decode('utf-8') for user in ldap_users}

        # Get GameVault users
        gamevault_users = get_gamevault_users()
        gamevault_usernames = {user['username'] for user in gamevault_users}

        # Create or update GameVault users based on LDAP
        for user in ldap_users:
            create_or_update_gamevault_user(user)

        # Delete GameVault users not in LDAP
        users_to_delete = gamevault_usernames - ldap_usernames
        for username in users_to_delete:
            delete_gamevault_user(username)
            
        print("User synchronization completed successfully.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
