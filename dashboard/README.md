# Updating dashboard

To build a new binary and upload it to the GCE instance:

```
go build --ldflags '-linkmode external -extldflags=-static' && \
gcloud compute ssh --project "sanitizer-bots" --zone "us-east1-d" dashboard-v2 --command "sudo rm -f /opt/sanitizers" && \
gcloud compute --project "sanitizer-bots" scp --zone "us-east1-d" sanitizers "dashboard-v2:/opt" && \
gcloud compute ssh --project "sanitizer-bots" --zone "us-east1-d" dashboard-v2 --command "sudo chown root:root /opt/sanitizers"
```

or 

```
go build --ldflags '-linkmode external -extldflags=-static' && \
gcloud compute config-ssh --remove && gcloud compute config-ssh --force-key-file-overwrite && \
ssh dashboard-v2.us-east1-d.sanitizer-bots "sudo rm -f /opt/sanitizers" && \
scp sanitizers "dashboard-v2.us-east1-d.sanitizer-bots:/opt" && \
ssh dashboard-v2.us-east1-d.sanitizer-bots "sudo chown root:root /opt/sanitizers"
```

Note: If you get a message about "scp: /opt/sanitizers: Text file busy", wait a
few seconds and try again.
