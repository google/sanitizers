# Sanitizer Dashboard

The dashboard is automatically built and updated from `master` on the GCE instance via [`start_script.sh`](start_script.sh).

## Creating the GCE instance

```bash
gcloud compute instances create dashboard-v3 \
  --project="sanitizer-bots" \
  --zone="us-east1-d" \
  --machine-type="e2-micro" \
  --network-tier="STANDARD" \
  --address="35.207.33.19" \
  --tags="http-server,https-server" \
  --no-service-account \
  --no-scopes \
  --shielded-secure-boot \
  --shielded-vtpm \
  --shielded-integrity-monitoring \
  --image-family="debian-13" \
  --image-project="debian-cloud" \
  --boot-disk-size="10GB" \
  --metadata=startup-script='#! /bin/bash
# for logs: sudo journalctl -u google-startup-scripts.service
set -x
which curl || (apt-get update && apt-get install -y curl)
while true; do
  curl -fL https://raw.githubusercontent.com/google/sanitizers/master/dashboard/start_script.sh | bash
  sleep 600
done'
```
