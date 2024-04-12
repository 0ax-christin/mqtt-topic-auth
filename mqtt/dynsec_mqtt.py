import subprocess
from dotenv import load_dotenv
import os

load_dotenv()

options = [
    "-u",
    os.getenv("ADMIN_USERNAME"),
    "-h",
    os.getenv("HOST"),
    "-P",
    os.getenv("ADMIN_PASSWORD"),
    "-V",
    "5",
]

mosquitto_base_cmd = ["mosquitto_ctrl"] + options + ["dynsec"]


def create_client(username: str, client_id: str) -> subprocess.CompletedProcess:
    add_client_id = []
    if client_id is not None:
        add_client_id = ["-i", client_id]
    create_client_result = subprocess.run(
        mosquitto_base_cmd + ["createClient", username] + add_client_id,
        input="\n",
        text=True,
    )
    return create_client_result


def create_role(role_name: str) -> subprocess.CompletedProcess:
    create_acl_role_result = subprocess.run(
        mosquitto_base_cmd + ["createRole", role_name]
    )
    return create_acl_role_result


def add_role_acl(
    role_name: str, acl_type: str, topic_filter: str, access: str, priority: str
) -> subprocess.CompletedProcess:
    acl_type_list = [
        "publishClientSend",
        "publishClientReceive",
        "subscribeLiteral",
        "subscribePattern",
        "unsubscribeLiteral",
        "unsubscribePattern",
    ]
    access_list = ["allow", "deny"]
    if acl_type not in acl_type_list:
        raise ValueError("Acl type not in accepted values")
    if access not in access_list:
        raise ValueError("Only allow or deny are accepted as values")
    add_acl_result = subprocess.run(
        mosquitto_base_cmd
        + ["addRoleACL", role_name, acl_type, topic_filter, access, priority]
    )
    return add_acl_result


def create_group(group_name: str) -> subprocess.CompletedProcess:
    create_group_result = subprocess.run(
        mosquitto_base_cmd + ["createGroup", group_name]
    )
    return create_group_result


def add_group_role(
    group_name: str, role_name: str, priority: str
) -> subprocess.CompletedProcess:
    add_group_role_result = subprocess.run(
        mosquitto_base_cmd + ["addGroupRole", group_name, role_name, priority]
    )
    return add_group_role_result


def add_group_client(
    group_name: str, username: str, priority: str
) -> subprocess.CompletedProcess:
    add_group_client_result = subprocess.run(
        mosquitto_base_cmd + ["addGroupClient", group_name, username, priority]
    )
    return add_group_client_result


def set_client_password(username: str, password: str) -> subprocess.CompletedProcess:
    set_password_result = subprocess.run(
        mosquitto_base_cmd + ["setClientPassword", username, password]
    )
    return set_password_result


# Disable Client of given username if they fail to solve the nonce
def disable_client(username: str) -> subprocess.CompletedProcess:
    disable_client_result = subprocess.run(
        mosquitto_base_cmd + ["disableClient", username]
    )
    return disable_client_result


# Remove a client of given username if they fail to solve the nonce
def remove_group_client(group_name: str, username: str) -> subprocess.CompletedProcess:
    remove_group_client_result = subprocess.run(
        mosquitto_base_cmd + ["removeGroupClient", group_name, username]
    )
    return remove_group_client_result


# For a given username of a client and a given mqtt topic for the purposes of authentication
# denoted by "auth-*", create a group and role relating to the mqtt username
# To the group, add as member only the admin and the given client
# Add the 4 ACLs to the role relating to publishing, subscribing and unsubscribing to the given auth topic
# Add this role to the group
# As the admin and client are members of the group, the ACLs apply to them for the given auth topic, allowing only these
# two parties to publish and subscribe
def set_dynsec_topic(mqtt_username: str, mqtt_topic: str) -> None:
    mqtt_acl = f"{mqtt_username}-acl"
    mqtt_group = f"{mqtt_username}-group"

    create_role(mqtt_acl)
    create_group(mqtt_group)
    add_group_role(mqtt_group, mqtt_acl, "1")
    add_group_client(mqtt_group, mqtt_username, "1")
    add_group_client(mqtt_group, "admin", "1")

    add_role_acl(mqtt_acl, "publishClientSend", mqtt_topic, "allow", "1")
    add_role_acl(mqtt_acl, "publishClientReceive", mqtt_topic, "allow", "1")
    add_role_acl(mqtt_acl, "subscribeLiteral", mqtt_topic, "allow", "1")
    add_role_acl(mqtt_acl, "unsubscribeLiteral", mqtt_topic, "allow", "1")
