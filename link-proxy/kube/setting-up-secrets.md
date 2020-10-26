# GCP DNS

This is needed for Let's Encrypt to get the wildcard cert.

First, create the DNS zone if you haven't, by running
`scripts/create-dns-zone.sh`.

Now, go to IAM in the console, and create a new role with these permissions:
* `dns.changes.create`
* `dns.changes.get`
* `dns.managedZones.list`
* `dns.resourceRecordSets.create`
* `dns.resourceRecordSets.delete`
* `dns.resourceRecordSets.list`
* `dns.resourceRecordSets.update`

Now create a service account, and add this role to the service account.

Create a new key for the service account. Use type JSON and save it as
`google.json`.

Finally, create the secret in kubernetes by running

```
$ kubectl -n link-proxy create secret generic gcp-dns-secret --from-file=./google.json
```

More info: https://github.com/certbot/certbot/blob/270b5535e24fd3dab4c05fa8929adca8117942f1/certbot-dns-google/certbot_dns_google/__init__.py


# Customer cluster service account

This is needed to get node-controller info and certs from the customer cluster
apiserver.

With your context in the customer cluster, run
`scripts/make-kubeconfig-link.sh`, and capture the output in a file called
`config`.

Then, back in the manager cluster context, run

```
$ kubectl -n link-proxy create secret generic customer-cluster-kubeconfig --from-file=config
```
