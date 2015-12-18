To build a new binary and upload it to the GCE instance:

$ go build
$ gcloud compute --project "sanitizer-bots" copy-files --zone "us-east1-d" dashboard "dashboard:/opt"
