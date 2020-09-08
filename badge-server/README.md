# badge-server

The badge server serves the README badge for GitHub projects that boot their
demos on blimp.

## Deployment

Because the badge server doesn't change much, it's built and deployed manually.

### Updating

1. Build the image and push it to gcr.

   ```
   docker build -t gcr.io/kelda-blimp/badge-server:latest .
   docker push gcr.io/kelda-blimp/badge-server:latest
   ```

1. Rollout the image

   ```
   kubectl rollout restart -n badge-server deployment/badge-server
   ```

### Kube YAML

The Kube YAML is hardcoded to work for prod. If you're deploying it elsewhere, update the `loadBalancerIP` in `kube/service.yaml`.

Then, run `kubectl apply -f ./kube`.
