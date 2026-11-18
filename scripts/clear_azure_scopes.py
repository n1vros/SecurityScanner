from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient

# =============================================================================
# CONFIGURATION (Use the same as your lottery script)
# =============================================================================
TENANT_ID = ""
CLIENT_ID = ""
CLIENT_SECRET = ""
SUBSCRIPTION_ID = ""

RG_PREFIX = ""
# =============================================================================

auth = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
res_client = ResourceManagementClient(auth, SUBSCRIPTION_ID)


def cleanup_all_groups():
    print(f"[*] Fetching all Resource Groups in subscription...")
    groups = res_client.resource_groups.list()

    deleted_count = 0
    for rg in groups:
        # Check if the RG name starts with your prefix
        if rg.name.startswith(RG_PREFIX):
            print(f"[-] Found {rg.name}. Initiating deletion...")
            try:
                # We don't use .result() here so we can trigger all deletes
                # simultaneously without waiting for each one to finish.
                res_client.resource_groups.begin_delete(rg.name)
                deleted_count += 1
            except Exception as e:
                print(f"    [!] Failed to delete {rg.name}: {e}")

    if deleted_count == 0:
        print("[*] No matching Resource Groups found.")
    else:
        print(f"\n[OK] Triggered deletion for {deleted_count} groups.")
        print("[!] Note: It may take 5-10 minutes for Azure to fully remove them from the Portal.")


if __name__ == "__main__":
    cleanup_all_groups()