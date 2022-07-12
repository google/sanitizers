To build a new binary and upload it to the GCE instance:

$ go build
$ gcloud compute --project "sanitizer-bots" scp --zone "us-east1-d" sanitizers "dashboard-v2:/opt"

Note: If you get a message about "scp: /opt/sanitizers: Text file busy", wait a
few seconds and try again.
