import os
import sys
import subprocess

def run_check_keys():
    print("Running key check script...")
    subprocess.run(["python", "/app/spire/check_keys.py"], check=True)

def run_replica(replica_id):
    print(f"Starting Spire Replica {replica_id}...")

    spines_int_cmd = f"cd /app/spire/spines/daemon && ./spines -p 8100 -c spines_int.conf -I 192.168.101.10{replica_id}"
    spines_ext_cmd = f"cd /app/spire/spines/daemon && ./spines -p 8120 -c spines_ext.conf -I 192.168.101.10{replica_id}"
    sm_cmd = f"cd /app/spire/scada_master && ./scada_master {replica_id} {replica_id} 192.168.101.10{replica_id}:8100 192.168.101.10{replica_id}:8120"
    prime_cmd = f"cd /app/spire/prime/bin && ./prime -i {replica_id} -g {replica_id}"

    sp_proc = subprocess.Popen(spines_int_cmd, shell=True, stdout=sys.stdout, stderr=sys.stderr)
    subprocess.Popen(spines_ext_cmd, shell=True, stdout=sys.stdout, stderr=sys.stderr)
    subprocess.Popen(sm_cmd, shell=True, stdout=sys.stdout, stderr=sys.stderr)
    subprocess.Popen(prime_cmd, shell=True, stdout=sys.stdout, stderr=sys.stderr)

    sp_proc.communicate()  # Keep container running

def run_client():
    print("Starting Spire Client...")

    spines_ext_cmd = "cd /app/spire/spines/daemon && ./spines -p 8120 -c spines_ext.conf -I 192.168.101.107"
    
    sp_proc = subprocess.Popen(spines_ext_cmd, shell=True, stdout=sys.stdout, stderr=sys.stderr)
    sp_proc.communicate()  # Keep container running

if __name__ == "__main__":
    run_check_keys()

    spire_mode = os.getenv("SPIRE_MODE", "replica")
    if spire_mode == "replica":
        spire_id = os.getenv("SPIRE_ID")
        if not spire_id:
            print("ERROR: SPIRE_ID must be set for replicas!")
            sys.exit(1)
        run_replica(spire_id)
    elif spire_mode == "client":
        run_client()
    else:
        print("ERROR: Unknown SPIRE_MODE! Must be 'replica' or 'client'.")
        sys.exit(1)
