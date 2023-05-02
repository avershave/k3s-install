#!/bin/bash

###                                ###  
# Please run prep for first time use #
###                                ###

set -aebpf

source ./env
source ./utils

HAS_METALLB="$(kubectl get namespace metallb-system &> /dev/null && echo true || echo false)"
HAS_NGINX="$(kubectl get namespace nginx &> /dev/null && echo true || echo false)"
HAS_LONGHORN="$(kubectl get namespace longhorn-system &> /dev/null && echo true || echo false)"
HAS_POSTGRES="$(helm status postgresql &> /dev/null && echo true || echo false)"
HAS_NFS="$(helm status nfs-server-provisioner &> /dev/null && echo true || echo false)"
HAS_GITLAB="$(helm status gitlab &> /dev/null && echo true || echo false)"

################################# prep ################################
function prep () {
    if [ $(ping -c 1 -q google.com >&/dev/null; echo $?) -eq 0 ]; then
        apt update
        apt install apt-transport-https ca-certificates curl software-properties-common \
        apache2-utils jq unzip rename python3 postgresql-client vim sshpass snapd wget ansible -y

        curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
        chmod +x kubectl
        sudo mv kubectl /usr/local/bin/kubectl

        curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

        curl -sLo /usr/local/bin/cfssl https://github.com/cloudflare/cfssl/releases/download/v1.6.3/cfssl_1.6.3_linux_amd64
        curl -sLo /usr/local/bin/cfssljson https://github.com/cloudflare/cfssl/releases/download/v1.6.3/cfssljson_1.6.3_linux_amd64
        chmod +x /usr/local/bin/cfssl*
    else
        echo - No Internet Available
        tar -zxvf prep/helm-v3.11.1-linux-amd64.tar.gz -C prep/
        mv prep/kubectl /usr/local/bin/kubectl
        mv linux-amd64/helm /usr/local/bin/helm
        mv prep/cfssl* /usr/local/bin/

    fi
    ## Gen Random Passwords
    gen_random

    helm repo add bitnami https://charts.bitnami.com/bitnami
    helm repo add runix https://helm.runix.net/
    helm repo add nicholaswilde https://nicholaswilde.github.io/helm-charts/
    helm repo add kvaps https://kvaps.github.io/charts
    helm repo add gitea https://dl.gitea.io/charts/
    helm repo add sei https://helm.cyberforce.site/charts
    helm repo add stackstorm https://helm.stackstorm.com/
    helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
    helm repo add longhorn https://charts.longhorn.io
    helm repo add bitnami https://charts.bitnami.com/bitnami
    helm repo add metallb https://metallb.github.io/metallb
    helm repo update

    echo "Please install nfs-common on all k3s nodes."
}

################################# certificates ################################
function certificates () {
    [ "$UID" -eq 0 ] || { echo "Please run the certificates command as sudo."; exit 1;}
    envsubst < certificates/host-template.json > certificates/host.json
    cfssl gencert -initca certificates/root-ca.json | cfssljson -bare root-ca
    cfssl gencert -ca certificates/root-ca.pem -ca-key certificates/root-ca-key.pem -config certificates/config.json \
                -profile intca certificates/int-ca.json | cfssljson -bare int-ca
    cfssl gencert -ca certificates/int-ca.pem -ca-key certificates/int-ca-key.pem -config certificates/config.json \
                -profile server certificates/host.json | cfssljson -bare host

    # Create pkcs12 host bundle for identity signing key
    openssl pkcs12 -export -out certificates/host.pfx -inkey certificates/host-key.pem -in certificates/host.pem \
                -passin pass:foundry -passout pass:foundry

    cp certificates/root-ca.pem /usr/local/share/ca-certificates/foundry-appliance-root-ca.crt
    update-ca-certificates

    kubectl create secret tls appliance-cert --key certificates/host-key.pem --cert <( cat certificates/host.pem certificates/int-ca.pem ) --dry-run=client -o yaml | kubectl apply -f -
    kubectl create secret generic appliance-root-ca --from-file=appliance-root-ca=certificates/root-ca.pem --dry-run=client -o yaml | kubectl apply -f -
    curl -#OL https://$VSPHERE_SERVER/certs/download.zip
    unzip download.zip -d certificates/vsphere
    kubectl create configmap appliance-root-ca --from-file=root-ca.crt=certificates/root-ca.pem --from-file=vsphere-ca.crt=certificates/vsphere.pem --dry-run=client -o yaml | kubectl apply -f -
}

################################# metallb ################################
function metallb () {
    helm upgrade -i metallb metallb/metallb --namespace metallb-system --create-namespace --wait --timeout 2m
    envsubst < values/metallb/metallb-ip.yaml | kubectl apply -f -
    kubectl apply -f values/metallb/metallb-l2advertise.yaml
}

################################# ingress-nginx ################################
function ingress-nginx () {
    if [ "${HAS_METALLB}" != "true" ]; then
        echo "Metallb Required"
        exit 1
    fi
    helm upgrade -i nginx ingress-nginx/ingress-nginx --namespace nginx --create-namespace --set controller.watchIngressWithoutClass=true --set controller.kind=Deployment --set controller.ingressClassResource.name=nginx --set controller.ingressClassResource.default=true --set controller.ingressClass=nginx
}

################################# rancher ################################
# Using custom cert -- replace staging if needed
function rancher () {
    if [ "${HAS_NGINX}" != "true" ]; then
        echo "Ingress-Nginx Required"
        exit 1
    fi
    helm upgrade -i rancher rancher-stable/rancher --namespace cattle-system --create-namespace --set bootstrapPassword=$RANCHER_PASS --set replicas=1 --set auditLog.level=2 --set auditLog.destination=hostPath --set hostname=rancher.$DOMAIN --set ingress.tls.source=secret --set ingress.tls.secretName=appliance-cert --wait
    kubectl create secret tls appliance-cert --key certificates/host-key.pem --cert <( cat certificates/host.pem certificates/int-ca.pem ) --dry-run=client -o yaml | kubectl apply -f - --namespace cattle-system
    echo "Rancher Password: $RANCHER_PASS"
}

################################# longhorn ################################
# Not setting ingress because we're going to be using Rancher
# If not using Rancher, set the ingress
function longhorn () {
    helm upgrade -i longhorn longhorn/longhorn --namespace longhorn-system --create-namespace --set persistance.defaultClassReplicaCount=1 --wait
    kubectl create secret tls appliance-cert --key certificates/host-key.pem --cert <( cat certificates/host.pem certificates/int-ca.pem ) --dry-run=client -o yaml | kubectl apply -f - --namespace longhorn-system
}

################################# postgresql ################################
function postgresql () {
    if [ "${HAS_LONGHORN}" != "true" ]; then
        echo "Longhorn Required"
        exit 1
    fi
    helm upgrade -i postgresql bitnami/postgresql --set global.storageClass=longhorn --set global.postgresql.auth.postgresPassword=$POSTGRES_PASS
    envsubst < values/postgresql/pgadmin4.values.yaml | helm upgrade -i pgadmin runix/pgadmin4 -f -
    echo "Postgres Password: $POSTGRES_PASS"
}

################################# nfs ################################
function nfs () {
    envsubst < values/nfs/nfs-server-provisioner.values.yaml | helm upgrade -i nfs-server-provisioner kvaps/nfs-server-provisioner -f -
    kubectl patch deploy nginx-ingress-nginx-controller -n nginx --type 'json' --patch \
    '[{"op": "add", "path": "/spec/template/spec/containers/0/ports/-", "value": {"name":"nfs-tcp","hostPort":2049,"containerPort":2049,"protocol":"TCP"}}]'
    kubectl patch deploy nginx-ingress-nginx-controller -n nginx --type 'json' --patch \
    '[{"op": "add", "path": "/spec/template/spec/containers/0/ports/-", "value": {"name":"nfs-udp","hostPort":2049,"containerPort":2049,"protocol":"UDP"}}]'
    envsubst < values/nfs/nfs-ingress.yaml | kubectl apply -f - --dry-run=client -o yaml | kubectl apply -f -
}

################################# identity ################################
function identity () {
    if [ "${HAS_POSTGRES}" != "true" ]; then
    echo "Postgresql Required"
    exit 1
    fi
    sed -ri "s|(signer:) \"\"|\1 $(base64 -w0 certificates/host.pfx)|" values/foundry/identity.values.yaml
    envsubst < values/foundry/identity.values.yaml | helm upgrade -i identity sei/identity -f -
    echo "Administrator pass: $GLOBAL_ADMIN_PASS"
    echo "2Factor Bypass: 123456"
}

################################# gitea ################################
function gitea () {
if [ "${HAS_POSTGRES}" != "true" ]; then
    echo "Postgresql Required"
    exit 1
fi
git config --global init.defaultBranch main
envsubst '$POSTGRES_PASS' < values/postgresql/postgres.job.yaml | kubectl apply -f -
sleep 5
kubectl create secret generic gitea-oauth-client --from-literal=key=gitea-client --from-literal=secret=$GITEA_OAUTH_CLIENT_SECRET
kubectl create secret generic gitea-admin-creds --from-literal=username=administrator --from-literal=password=$GLOBAL_ADMIN_PASS
envsubst < values/gitea/gitea.values.yaml | helm upgrade -i gitea gitea/gitea -f - --wait --timeout 5m

MKDOCS_DIR=mkdocs/
CURL_OPTS=( --header "accept: application/json" --header "Content-Type: application/json" )
REQ=$( curl "${CURL_OPTS[@]}" \
                --user administrator:$GLOBAL_ADMIN_PASS \
                --request DELETE "https://$DOMAIN/gitea/api/v1/users/administrator/tokens/appliance-setup"
)
USER_TOKEN=$( curl "${CURL_OPTS[@]}" \
                --user administrator:$GLOBAL_ADMIN_PASS \
                --request POST "https://$DOMAIN/gitea/api/v1/users/administrator/tokens" \
                --data "{ \"name\": \"appliance-setup\"}" | jq -r '.sha1'
)

# Set git user vars
git config --global user.name "administrator"
git config --global user.email "administrator@$DOMAIN"

# Create foundry-docs organization
curl "${CURL_OPTS[@]}" \
  --request POST "https://$DOMAIN/gitea/api/v1/orgs?access_token=$USER_TOKEN" \
  --data @- <<EOF
{
  "username": "k3s-savage",
  "repo_admin_change_team_access": true
}
EOF

# Create repo
# for repo in $(find $DOCS_DIR -maxdepth 1 -mindepth 1 -type d -printf '%P\n'); do
curl "${CURL_OPTS[@]}" \
    --request POST "https://$DOMAIN/gitea/api/v1/orgs/k3s-savage/repos?access_token=$USER_TOKEN" \
    --data @- <<EOF
{
  "name": "mkdocs",
  "private": false,
  "default_branch": "main"
}
EOF

git -C $MKDOCS_DIR init
git -C $MKDOCS_DIR add -A
git -C $MKDOCS_DIR commit -m "Initial commit" || true
git -C $MKDOCS_DIR push -u https://administrator:$GLOBAL_ADMIN_PASS@$DOMAIN/gitea/k3s-savage/mkdocs.git --all
}

################################# topomojo ################################
function topomojo () {
    if [ "${HAS_POSTGRES}" != "true" ]; then
    echo "Postgresql Required"
    exit 1
    fi
    # cat certificates/root-ca.pem certificates/vsphere.pem | sed 's/^/        /' | sed -i -re 's/(cacert.crt:).*/\1 |-/' -e '/cacert.crt:/ r /dev/stdin' values/foundry/topomojo.values.yaml
    envsubst < values/foundry/topomojo-pv.yaml | kubectl apply -f -
    kubectl apply -f values/foundry/topomojo-pvc.yaml
    envsubst '$DOMAIN' < values/foundry/console-ingress.yaml | kubectl apply -f -
    envsubst < values/foundry/topomojo.values.yaml | helm upgrade -i topomojo sei/topomojo -f -
}

################################# gitlab ################################
function gitlab () {
  if [ "${HAS_POSTGRES}" != "true" ]; then
      echo "Postgresql Required"
      exit 1
  fi
  exports_path="values/crucible/seed/gitlab"
  timeout=0
  max_timeout=1200
  gitlab_token=$(awk '/Terraform__GitlabToken/ {print $2}' values/crucible/caster.values.yaml | tr -d '"')
  modules_group="caster-modules"
  admin_uid=$(awk '/Account__AdminGuid/ {print $2}' values/foundry/identity.values.yaml | tr -d '"')
  gitlab_group_id=$(awk '/Terraform__GitlabGroupId/ {print $2}' values/crucible/caster.values.yaml | tr -d '"')
  gitlab_host="https://gitlab.$DOMAIN"
  gitlab_user="administrator@$DOMAIN"
  gitlab_password="foundry"
  api_url="https://gitlab.$DOMAIN/api/v4"
  gitlab_url="gitlab.$DOMAIN"

  # kubectl exec postgresql-0 -- psql "postgresql://postgres:$POSTGRES_PASS@localhost" -c "CREATE DATABASE gitlab_db;"
  # envsubst < values/crucible/gitlab.secrets.yaml | kubectl apply -f -
  # envsubst < values/crucible/gitlab-min.values.yaml | helm upgrade -i gitlab gitlab/gitlab -f - --wait --timeout 6m

  # kex_q gitlab-toolbox gitlab-rails runner -q"u = User.create_or_find_by(username: 'root', email: 'administrator@${domain}', name: 'Administrator' , password: '$GLOBAL_ADMIN_PASS', password_confirmation: '$GLOBAL_ADMIN_PASS', admin: true); u.skip_confirmation=true; u.save"
  # kex_q gitlab-toolbox gitlab-rails runner -q"token = User.find_by_username('root').personal_access_tokens.create(scopes: [:api], name: 'root seed token'); token.set_token('${gitlab_token}'); token.save!"

  h_auth="Private-Token: ${gitlab_token}"
  h_json="Content-Type: application/json"

  # Set root to admin@${domain}
  req=$(curl -ks --location --request GET "${api_url}/users?username=root")
  user_id=$(echo ${req} | jq -j '.[0] | .id')
  data_json=$(echo ${req} | jq --arg admin_uid "${admin_uid}" '.[0] | .provider = "identity" | .extern_uid = $admin_uid')
  req=$(curl -k --location --request PUT "${api_url}/users/${user_id}" \
  --header "${h_json}" \
  --header "${h_auth}" \
  --data "${data_json}")
  echo "UserId: ${user_id}"
  echo $req | jq .

  # Check if the group exists by name
  req=$(curl -ks --location --request GET "${api_url}/groups?search=${modules_group}" \
  --header "${h_json}" \
  --header "${h_auth}")
  echo $req | jq .

  group=$(echo ${req} | jq --arg name "${modules_group}" '.[] | select(.name=$name)')
  gitlab_group_id=$(echo ${group} | jq -j '.id')

  if [[ -z ${group} ]]; then

    # Create caster modules group
    data_json=$(cat <<EOF
      {
        "name": "${modules_group}",
        "path": "${modules_group}",
        "visibility": "public"
      }
EOF
  )

    req=$(curl -ks --location --request POST "${api_url}/groups" \
    --header "${h_json}" \
    --header "${h_auth}" \
    --data "${data_json}")
    echo ${req} | jq .
    gitlab_group_id=$(echo ${req} | jq -j '.id')
    
  fi

# Import all projects into group, file name without the extension will be the repo name.
  files=$(find ${exports_path} -type f -iname "*.tar.gz" | sed "s/.*\///; s/\.tar.gz//")
  cd ${exports_path}
  for file in ${files}; do
    # Gitlab has terrible support for repos exported with different versions of gitlab
    # We need to extract the repo 
    mkdir -p "${file}" && tar -xzf ${file}.tar.gz --overwrite -C $file
    
    git clone --mirror "${file}/project.bundle" "${file}/.git"
    git -C ${file} init
    git -C ${file} checkout 
    git -C ${file} status
    git -C ${file} remote remove origin
    #Create project
    data_json=$(cat <<EOF
        {
          "name": "${file}",
          "namespace_id": ${gitlab_group_id},
          "visibility": "public"
        }
EOF
      )

    req=$(curl -k --location --request POST "${api_url}/projects" \
      --header "${h_json}" \
      --header "${h_auth}" \
      --data "${data_json}")
    project_id=$(echo ${req} | jq '.id')
    if [[ -n "$project_id" ]]; then 
      git -C ${file} remote add origin "$gitlab_host/${modules_group}/${file}.git"
      git -C ${file} push -u https://root:$GLOBAL_ADMIN_PASS@${gitlab_url}/${modules_group}/${file}.git --all
      git -C ${file} push -u https://root:$GLOBAL_ADMIN_PASS@${gitlab_url}/${modules_group}/${file}.git --tags
    fi
    # cleanup
    rm -rf ${file}
    sleep 3
  done
  cd ../../../
}
################################# crucible ################################
function crucible () {
    if [ "${HAS_POSTGRES}" != "true" ]; then
    echo "Postgresql Required"
    exit 1
    fi
    envsubst < values/crucible/alloy.values.yaml | helm upgrade -i alloy sei/alloy -f -
    envsubst < values/crucible/caster.values.yaml | helm upgrade -i caster sei/caster -f -
    envsubst < values/crucible/player.values.yaml | helm upgrade -i player sei/player -f -

    # get MOID for steamfitter
    echo "Attempting to get vsphere cluster"
    MOID=$(pwsh -c 'Connect-VIServer -server $env:VSPHERE_SERVER -user $env:VSPHERE_USER -password $env:VSPHERE_PASS | Out-Null; Get-Cluster -Name $env:VSPHERE_CLUSTER | select -ExpandProperty id')
    MOID=$(echo "${MOID}" | rev | cut -d '-' -f 1,2 | rev)
    if [[ -n ${MOID} ]]; then
    sed -i "s/VmTaskProcessing__ApiParameters__clusters:.*/VmTaskProcessing__ApiParameters__clusters: ${MOID}/" "steamfitter.values.yaml"
    echo "vsphere cluster set"
    fi

    envsubst < values/crucible/steamfitter.values.yaml | helm upgrade -i steamfitter sei/steamfitter -f -
    envsubst < values/crucible/mongodb.values.yaml | helm upgrade -i mongodb bitnami/mongodb -f -
    envsubst < values/crucible/stackstorm-min.values.yaml | helm upgrade -i stackstorm stackstorm/stackstorm-ha -f - --wait --timeout 10m

    git -C $MKDOCS_DIR add -A || true
    git -C $MKDOCS_DIR commit -m "Add Crucible Docs" || true
    git -C $MKDOCS_DIR push -u https://administrator:$GLOBAL_ADMIN_PASS@$DOMAIN/gitea/foundry/mkdocs.git --all
}

################################# moodle ################################
function moodle () {
  kubectl config set-context --current --namespace=default

  #######################
  #   SETTING COLORS    #
  #######################
  RED='\033[0;31m'
  WHITE='\033[1;37m'
  NC='\033[0m' # NO COLOR

  cat << "EOF"
                                  .-..-.
    _____                         | || |
    /____/-.---_  .---.  .---.  .-.| || | .---.
    | |  _   _  |/  _  \/  _  \/  _  || |/  __ \
    * | | | | | || |_| || |_| || |_| || || |___/
      |_| |_| |_|\_____/\_____/\_____||_|\_____)
EOF

  echo -e "${WHITE}Waiting for Moodle to start up, this can take ~6m${NC}"
  echo -e "${WHITE}You can always check the progress with kubectl get pods${NC}"
  # envsubst < values/moodle/moodle.values.yaml | helm install -f - moodle bitnami/moodle --wait --timeout 6m
  export moodlePodName=$(kubectl get pods | grep moodle | grep -v maria | awk '{print $1}')

  if [ -z "$moodlePodName" ]; then
    echo -e "${RED}moodlePodName NOT SET${NC}"
    exit 1
  fi


  echo -e "${WHITE}Applying moove theme and foundrysync tool${NC}"
  unzip -oq values/moodle/theme_moove.zip -d values/moodle/
  unzip -oq values/moodle/tool_foundrysync.zip -d values/moodle/
  kubectl cp ./values/moodle/moove $moodlePodName:/bitnami/moodle/theme/
  kubectl cp ./values/moodle/foundrysync $moodlePodName:/bitnami/moodle/admin/tool/
  kubectl exec -it $moodlePodName -- /bin/bash -c "php /bitnami/moodle/admin/cli/upgrade.php --non-interactive --allow-unstable"
  echo -e "${WHITE}DONE${NC}"

  echo -e "${WHITE}Setting theme to moove${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "php /bitnami/moodle/admin/cli/cfg.php --name=theme --set=boost"
  echo -e "${WHITE}DONE${NC}"

  echo -e "${WHITE}Increasing upload size to 500M${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "sed -i 's/40M/500M/' /opt/bitnami/php/etc/php.ini"
  echo -e "${WHITE}DONE${NC}"

  echo -e "${WHITE}Moodle cache settings${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "sed -i 's/;opcache.use_cwd=1/opcache.use_cwd=1/' /opt/bitnami/php/etc/php.ini"
  kubectl exec -it $moodlePodName -- /bin/bash -c "sed -i 's/;opcache.validate_timestamps=1/opcache.validate_timestamps=1/' /opt/bitnami/php/etc/php.ini"
  kubectl exec -it $moodlePodName -- /bin/bash -c "sed -i 's/;opcache.save_comments=1/opcache.save_comments=1/' /opt/bitnami/php/etc/php.ini"
  kubectl exec -it $moodlePodName -- /bin/bash -c "sed -i 's/;opcache.enable_file_override=0/opcache.enable_file_override=0/' /opt/bitnami/php/etc/php.ini"
  echo -e "${WHITE}DONE${NC}"

  #echo -e "${WHITE}OAuth2 Provider Setup${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "php /bitnami/moodle/admin/tool/foundrysync/cli/manage.php --baseurl='https://$DOMAIN/identity' --clientid=moodle-client --clientsecret=$IDENTITY_CLIENTSECRET --loginscopes='openid profile email alloy-api steamfitter-api caster-api' --loginscopesoffline='openid profile email alloy-api steamfitter-api caster-api' --name='Local Identity' --showonloginpage=true --image=https://$DOMAIN/identity/favicon.ico --requireconfirmation=false --json" > values/moodle/response.json
  ISSUER_CMD=$( cat values/moodle/response.json | jq '[ .success, (.data | .id) ] | @csv' | tr -d '"')

  IFS=',' read -r -a RESULT <<< $ISSUER_CMD

  if [ "${RESULT[0]}" != "true" ]; then
    echo -e "${RED}ERROR: ${RESULT[0]}"
    echo -e "${RED}Failed to create new OAuth2 issuer, exiting...${NC}"
    exit 1
  fi

  echo -e "${WHITE}OAuth2 Provider configured${NC}"

  echo -e "${WHITE}Setting theme_foundry id to newly created issuer...${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "php /bitnami/moodle/admin/cli/cfg.php --component=theme_moove --name=issuerid --set=${RESULT[1]}"
  echo -e "${WHITE}DONE${NC}"

  echo -e "${WHITE}Enabling oAuth2${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "php /bitnami/moodle/admin/cli/cfg.php --name=auth --set=oauth2,outage"
  echo -e "${WHITE}DONE${NC}"

  echo -e "${WHITE}==========Setting additional reccommended options==========${NC}"
  echo -e "${WHITE}Setting timezone${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "php /bitnami/moodle/admin/cli/cfg.php --name=timezone --set=America/New_York"
  echo -e "${WHITE}Turning off email change confirmation${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "php /bitnami/moodle/admin/cli/cfg.php --name=emailchangeconfirmation --set=0"
  echo -e "${WHITE}Setting country to US${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "php /bitnami/moodle/admin/cli/cfg.php --name=country --set=US"
  echo -e "${WHITE}Setting forcelogin${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "php /bitnami/moodle/admin/cli/cfg.php --name=forcelogin --set=1"
  echo -e "${WHITE}Setting forceloginforprofileimage${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "php /bitnami/moodle/admin/cli/cfg.php --name=forceloginforprofileimage --set=1"
  echo -e "${WHITE}Disabling guest login button${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "php /bitnami/moodle/admin/cli/cfg.php --name=guestloginbutton --set=0"
  echo -e "${WHITE}Setting enrol plugin settings${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "php /bitnami/moodle/admin/cli/cfg.php --name=enrol_plugins_enabled --set='manual,self,cohort'"
  echo -e "${WHITE}Disabling langmenu${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "php /bitnami/moodle/admin/cli/cfg.php --name=langmenu --set=0"
  echo -e "${WHITE}Disabling send course welcome message${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "php /bitnami/moodle/admin/cli/cfg.php --component=enrol_self --name=sendcoursewelcomemessage --set=0"
  echo -e "${WHITE}Disabling course end date${NC}"
  kubectl exec -it $moodlePodName -- /bin/bash -c "php /bitnami/moodle/admin/cli/cfg.php --component=moodlecourse --name=courseenddateenabled --set=0"
  echo -e "${WHITE}==========DONE==========${NC}"
}

################################# validate ################################
function validate () {
  echo - showing images
  kubectl get pods -A -o jsonpath="{.items[*].spec.containers[*].image}" | tr -s '[[:space:]]' '\n' |sort | uniq -c
}

################################# usage ################################
function usage () {
  echo ""
  echo "-------------------------------------------------"
  echo ""
  echo " Usage: $0 {certificates | appname | validate}"
  echo ""
  echo " $0 certificates # create and import staging certificates into default namespace ** NEEDS SUDO"
  echo " $0 metallb # deploy metallb"
  echo " $0 ingress-nginx # deploy metallb"
  echo " $0 rancher # deploy rancher"
  echo " $0 longhorn # deploy longhorn"
  echo " $0 postgresql # deploy postgresql"
  echo " $0 nfs # deploy nfs"
  echo " $0 gitea # deploy gitea"
  echo " $0 identity # deploy identity"
  echo " $0 topomojo # deploy topomojo"
  echo " $0 gitlab # deploy gitlab"
  echo " $0 crucible # deploy crucible"
  echo " $0 moodle # deploy moodle"
  echo " $0 validate # validate all the image locations"
  echo ""
  echo "-------------------------------------------------"
  exit 1
}

case "$1" in
        certificates) certificates;;
        metallb) metallb;;
        ingress-nginx) ingress-nginx;;
        rancher) rancher;;
        longhorn) longhorn;;
        nfs) nfs;;
        postgresql) postgresql;;
        gitea) gitea;;
        identity) identity;;
        topomojo) topomojo;;
        gitlab) gitlab;;
        crucible) crucible;;
        moodle) moodle;;
        validate) validate;;
        *) usage;;
esac