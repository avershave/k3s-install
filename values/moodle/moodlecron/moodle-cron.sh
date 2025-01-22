#!/bin/bash

# set context to where Moodle is located for this to work
POD_NAME=$(kubectl get pods | grep moodle | grep -v maria | awk '{print $1}')

kubectl --server=https://${KUBERNETES_SERVICE_HOST} --token=`cat /var/run/secrets/kubernetes.io/serviceaccount/token` --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  exec -n moodle $POD_NAME -- \
  /bin/bash -c "/opt/bitnami/php/bin/php /bitnami/moodle/admin/cli/cron.php" >> /bitnami/cron/moodle-cron.log 2>&1