## Create the Moodle Cron Script

``` bash
#!/bin/bash
POD_NAME=$(kubectl get pods -n moodle -l app=moodle -o jsonpath='{.items[0].metadata.name}')

kubectl --server=https://${KUBERNETES_SERVICE_HOST} --token=`cat /var/run/secrets/kubernetes.io/serviceaccount/token` --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  exec -n moodle $POD_NAME -- \
  /bin/bash -c "/opt/bitnami/php/bin/php /bitnami/moodle/admin/cli/cron.php" >> /bitnami/cron/moodle-cron.log 2>&1
```

Dynamically get the Moodle pod by using the attached label. Then, use the service account token and certificate to run `kubectl exec` into the Moodle pod.

## Create a ConfigMap with the Script

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: moodle-cron-script
  namespace: moodle
data:
  moodle-cron.sh: |
    #!/bin/bash
    POD_NAME=$(kubectl get pods -n moodle -l app=moodle -o jsonpath='{.items[0].metadata.name}')

    kubectl --server=https://${KUBERNETES_SERVICE_HOST} --token=`cat /var/run/secrets/kubernetes.io/serviceaccount/token` --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
      exec -n moodle $POD_NAME -- \
      /bin/bash -c "/opt/bitnami/php/bin/php /bitnami/moodle/admin/cli/cron.php" >> /bitnami/cron/moodle-cron.log 2>&1

```

Apply the ConfigMap:

```sh
kubectl apply -f moodle-cron-configmap.yaml
```

## Create a Service Account and Role Binding

The CronJob needs a service account to run under. Create the service account and assign the necessary permissions.

### Service Account

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: moodle-cron
  namespace: moodle
```

Apply it:

```sh
kubectl apply -f moodle-cron-sa.yaml
```

### Role and RoleBinding

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: moodle
  name: moodle-cron-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
```

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: moodle-cron-rolebinding
  namespace: moodle
subjects:
- kind: ServiceAccount
  name: moodle-cron
  namespace: moodle
roleRef:
  kind: Role
  name: moodle-cron-role
  apiGroup: rbac.authorization.k8s.io
```

Apply them:

```sh
kubectl apply -f moodle-cron-role.yaml
kubectl apply -f moodle-cron-rolebinding.yaml
```


## Deploy the Moodle CronJob

Now, define and apply the `CronJob`:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: moodle-php-cron
  namespace: moodle # check what namespace Moodle is in
  
spec:
  schedule: "* * * * *"  # runs every minute
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: moodle-cron
              image: bitnami/kubectl:latest
              securityContext:
                allowPrivilegeEscalation: false
                capabilities:
                  drop:
                  - ALL
                privileged: false
                readOnlyRootFilesystem: true
                runAsGroup: 1001
                runAsNonRoot: true
                runAsUser: 1001
              command: ["/opt/moodle-cron.sh"]
              volumeMounts:
                - name: cron-script
                  mountPath: /opt
          restartPolicy: OnFailure
          serviceAccountName: moodle-cron
          volumes:
            - name: cron-script
              configMap:
	              name: moodle-cron-script
	              defaultMode: 0777
```

Note that the ConfigMap is being mounted so that the script can be executed. Also, note that the permissions are set to `nonRoot` to maintain no root access to the pod.

Apply the CronJob:

```sh
kubectl apply -f moodle-cronjob.yaml
```


## Verify the Deployment

### Check CronJob

```sh
kubectl get cronjobs -n moodle
```

### Check if Jobs are Created

```sh
kubectl get jobs -n moodle
```

### Check Logs of the CronJob

```sh
kubectl logs -l job-name=<JOB_NAME> -n moodle
```

Replace `<JOB_NAME>` with the actual running job name.

### Manually Trigger a Job

If needed, manually start the cron job:

```sh
kubectl create job --from=cronjob/moodle-php-cron moodle-cron-manual -n moodle
```


## Troubleshooting

```sh
kubectl describe jobs -n moodle
```

  ```sh
  kubectl logs -l job-name=<JOB_NAME> -n moodle
 ```
 
 ```sh
   kubectl get jobs -n moodle --field-selector status.failed>0
```
