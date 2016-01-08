To build a new binary and upload it to the GCE instance:

$ go build -ldflags '-I /lib64/ld-linux-x86-64.so.2'
$ gcloud compute --project "sanitizer-bots" copy-files --zone "us-east1-d" dashboard "dashboard:/opt"
