---
layout: blank
pagetitle: Cloud Testing
---

## Resources

- [Hacking the Cloud](https://hackingthe.cloud/) is a fantastic resource for cloud pentesting TTPs
- [CloudSecDocs](https://cloudsecdocs.com/) is another solid reference
- [Bishop Fox: Bad Pods](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation) for K8s pod privesc
- [Lightspin: Red Kube](https://github.com/lightspin-tech/red-kube)

## AWS

**Credential Types**
- `AKIA...` prefixed access keys are long-term IAM User credentials
- `ASIA...` prefixed access keys are short-term STS credentials (could be a Role or User)
	- Short-term creds include an Access Key, Secret Access Key, and Session Token
- Validate with `aws sts get-caller-identity` (requires no IAM permissions)

**IAM Enumeration**
- List policies for a user:
	- `aws iam list-user-policies --user-name {username}`
	- `aws iam list-attached-user-policies --user-name {username}`
- Full IAM report: `aws iam get-account-authorization-details`
	- Returns all users, groups, roles, and policies with their relationships
- Simulate permissions: `aws iam simulate-principal-policy`
- Noisier automated tools: [Pacu](https://rhinosecuritylabs.com/aws/pacu-open-source-aws-exploitation-framework/), [enumerate-iam](https://github.com/andresriancho/enumerate-iam)
- OIDC providers: `aws iam list-open-id-connect-providers --no-cli-pager`
	- Filter GAAD for GitHub Actions federated trust:
	- `jq '.RoleDetailList[] | select(.AssumeRolePolicyDocument.Statement[] | .Principal.Federated? | type=="string" and contains("token.actions.githubusercontent.com")) | {"RoleName": .RoleName, "Arn": .Arn, "AssumeRolePolicyDocument": .AssumeRolePolicyDocument}' gaad.json`
	- If the ARPD conditions are over-scoped (e.g. `repo:org/prefix-*:*` without branch protection), any user with write access to a matching repo can assume the role

**EC2 Instance Metadata (IMDS)**
- `curl http://169.254.169.254/latest/meta-data/`
	- Contains IAM info, networking info, security groups, subnets, etc.
	- IPv6: check `fd00:ec2::254`
	- ECS tasks have their own metadata endpoint
- IMDS v2 (token required):
	- `TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")`
	- `curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/`
- Check IMDS config for an instance:
	- `aws ec2 describe-instances --instance-id {id} | jq '.Reservations[].Instances[].MetadataOptions'`

**Secrets Locations**
- Secrets can show up in a lot of places beyond Secrets Manager
	- EC2 userData: `for i in $(aws ec2 describe-instances | jq -r '.Reservations[] | .Instances[].InstanceId'); do aws ec2 describe-instance-attribute --instance-id $i --attribute userData; done`
	- CloudFormation stack params/outputs and templates
	- DynamoDB tables (sample with `aws dynamodb scan --max-items=25 --table-name={table}`)
	- ECS task definitions (environment variables)
	- ECR container images and `docker history`
	- Lambda function code, environment variables, and logs
	- SSM Documents and Parameters
	- Step Function execution inputs/outputs
	- S3 buckets
	- AppSync API keys (format: `da2-[a-z0-9]{26}`)

**Shadow Resources**
- AWS services that use predictable S3 bucket naming can be preemptively created by an attacker
	- The attacker creates the bucket and allows writes from the target account
	- When the target tries to use the bucket, their data goes to the attacker's bucket
	- [Aqua Security research](https://www.aquasec.com/blog/bucket-monopoly-breaching-aws-accounts-through-shadow-resources/)

**Cognito**
- If self-signup is enabled, this could be an initial access vector
- Tampering user attributes: [Doyensec blog](https://blog.doyensec.com/2023/01/24/tampering-unrestricted-user-attributes-aws-cognito.html)

**Detection Avoidance**
- GuardDuty
	- Alerts on specific user agents (PenTest:IAMUser findings)
		- [Bypass GuardDuty user agent detection](https://hackingthe.cloud/aws/avoiding-detection/guardduty-pentest/)
	- If working with exfiltrated instance profile creds, running from an EC2 in your own VPC with VPC Endpoints can slip by GuardDuty
- Reverse shells
	- Use low ports (80/443) to mimic normal traffic, avoid printing attacker IP in bash history

**MFA CLI Session**
- `aws sts get-session-token --serial-number arn:aws:iam::{ACCOUNT_ID}:mfa/{DEVICE_NAME} --token-code {MFA_CODE} --duration-seconds 129600 --profile {PROFILE}`

**S3 Enumeration**
- Listing and downloading
	- `aws s3 ls` to list buckets
	- `aws s3 ls s3://{bucket}` to list objects
	- `aws s3 cp s3://{bucket}/{key} .` to download
- Pre-signed URLs
	- `aws s3 presign s3://{bucket}/{key} --expires-in 3600` to generate a pre-signed URL without needing public access
- Check bucket policies for overly permissive access (e.g. `s3:*` to `*` principal)

**STS AssumeRole**
- If you find a role you can assume:
	- `OUT=$(aws sts assume-role --role-arn arn:aws:iam::{ACCOUNT}:role/{ROLE} --role-session-name pwned); export AWS_ACCESS_KEY_ID=$(echo $OUT | jq -r '.Credentials.AccessKeyId'); export AWS_SECRET_ACCESS_KEY=$(echo $OUT | jq -r '.Credentials.SecretAccessKey'); export AWS_SESSION_TOKEN=$(echo $OUT | jq -r '.Credentials.SessionToken')`
- AWS CLI credential resolution order:
	- command line options > environment variables > `~/.aws/credentials` > `~/.aws/config` > container credentials > EC2 instance profile

**Automated Enumeration Tools**
- PMapper: identifies privesc paths and cross-account access
	- `pmapper --profile {profile} graph create`
	- `pmapper --profile {profile} query -s "preset privesc *"` (escalation paths from non-admin)
	- `pmapper --profile {profile} query -s "preset wrongadmin"` (roles that shouldn't be admin but are)
- Prowler: `prowler aws --profile {AWS_PROFILE} --status FAIL`
- Cloudfox: pulls info to help triage findings from other tools

## Azure

**CLI Basics**
- Authentication
	- `az login` (interactive) or `az login --use-device-code` (remote/headless)
	- Service principal: `az login --service-principal -u {app_id} -p {password_or_cert} --tenant {tenant}`
	- Check current user: `az ad signed-in-user show`
- Subscription management
	- List subscriptions: `az account list -o table`
	- Switch subscription: `az account set --subscription {SUBSCRIPTION_ID}`
- Resource enumeration
	- List resources: `az resource list`
	- List resource groups: `az group list`
	- List VMs: `az vm list`
- Run commands on VMs:
	- `az vm run-command invoke --resource-group {RG} --name {VM} --command-id RunPowerShellScript --scripts '{command}'`
- List role assignments: `az role assignment list --all`
- Recon (unauthenticated):
	- Federation info: `https://login.microsoftonline.com/getuserrealm.srf?login=username@{domain}&xml=1`
	- Tenant ID: `https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration`

**Key Vault**
- List vaults: `az keyvault list --query '[].name' --output tsv`
- With Contributor access, give yourself secret perms:
	- `az keyvault set-policy --name {vault} --upn {your_user} --secret-permissions get list`
- List secrets: `az keyvault secret list --vault-name {vault} --query '[].id' --output tsv`
- Get secret value: `az keyvault secret show --id {secret_uri}`

**Metadata Service**
- `curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"`
- Get access token:
	- `curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"`

**Automated Enumeration**
- Prowler: `az account set --subscription {SUB_ID}; prowler azure --az-cli-auth --status FAIL`
- [MicroBurst](https://github.com/NetSPI/MicroBurst) for storage blob enum, cert export, ACR dumps
- [PowerZure](https://github.com/hausec/PowerZure) for Azure security assessment
- [ROADTools](https://github.com/dirkjanm/ROADtools) for Azure AD interaction
- [MSOLSpray](https://github.com/dafthack/MSOLSpray) for password spraying Azure/O365

**Permission Model**
- Microsoft overloads a lot of terms, so use the following:
  - Azure RBAC - roles governing Azure resource management (control-plane) and data access (data-plane)
  - Microsoft Entra Roles - identity system administration, directory management, M365 service admin
  - Microsoft Graph Permissions - programmatic/application access to Microsoft cloud services
- Entra roles are for human admins, Graph permissions are for applications
	- There's overlap: Global Administrator (Entra) can do similar things to `Directory.ReadWrite.All + Application.ReadWrite.All` (Graph)
- Entra ID is the identity provider for M365, not a part of M365 itself

**Secrets Locations**
- VMs
	- Custom Script Extensions (non-protected settings readable by Readers), userData, VM Access Extension (older versions persist passwords), resource tags
- VMSS
	- Configuration files, osProfile, Custom Script Extensions, launch templates, instance metadata
- ARM Templates
	- Hardcoded secrets in templates, template specs, configuration files
- Function Apps
	- App Settings, Connection Strings, Function/Host Keys (need higher than Reader)
- Automation Accounts
	- Runbook source code (full scripts readable)
- Logic Apps
	- Workflow definitions contain trigger details and connection info
- DevOps
	- Pipeline definitions, build/release pipeline configs
- Data Factory
	- Pipeline configs, linked service configurations

## GCP

**CLI Basics**
- Project and org management
	- List projects: `gcloud projects list`
	- List organizations: `gcloud organizations list`
- Compute
	- List compute instances: `gcloud compute instances list`
- IAM
	- List service accounts: `gcloud iam service-accounts list`
	- List keys for a service account: `gcloud iam service-accounts keys list --iam-account {account}`
	- Get project IAM policy: `gcloud projects get-iam-policy {project}`
- Storage
	- List buckets: `gsutil ls gs://`
- `--impersonate-service-account` is a global flag available on most commands, even if docs don't say so
	- Try impersonating every service account you find, it may lead to privesc

**Metadata**
- `curl -sH "Metadata-Flavor: Google" 'http://169.254.169.254/computeMetadata/v1/?recursive=true&alt=text'`
- Get service accounts:
	- `curl -sH "Metadata-Flavor: Google" 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/'`
- Get access token:
	- `curl -sH "Metadata-Flavor: Google" 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/{account}/token'`
	- Still restricted by scopes

**IAM Enumeration**
- Enumerate folder IAM:
	- `for folder in $(cat folders.txt); do gcloud resource-manager folders get-iam-policy --format=json $folder > "${folder}-iam.json"; done`
- Enumerate project IAM:
	- `for i in $(cat projects.txt); do gcloud projects get-ancestors-iam-policy $i --format=json > "${i}_ancestor-iam-policy.json"; done`
- Project existence check:
	- "was not found" means it doesn't exist, "Required permission" means it exists but no access

**Domain-Wide Delegation (DWD)**
- If a service account has DWD, it can impersonate any user in the Workspace domain for the authorized scopes (Gmail, Drive, Calendar, etc.)
	- Users within a project may already be able to create keys for service accounts by default
	- Scopes vary, could be Drive-only, Gmail-only, or full admin
- Tools: [DeleFriend](https://github.com/axon-git/DeleFriend), [Delegate](https://github.com/lutzenfried/Delegate)
- Use cases:
	- GDrive access: Share files from privileged users' drives to your controlled user, mount and scan with Noseyparker/Titus
	- GCal access: Impersonate HR to send phishing calendar invitations

**Post-Exploitation**
- Service account key management
	- Create key for a service account: `gcloud iam service-accounts keys create {key_file} --iam-account {account_email}`
	- Activate service account: `gcloud auth activate-service-account {account} --key-file={key_file}`
- Auth management
	- List auth profiles: `gcloud auth list`
	- Switch account: `gcloud config set account {account_email}`
- SSH access
	- Add SSH key to instance metadata: `gcloud compute instances add-metadata {instance} --metadata-from-file ssh-keys=/tmp/root.pub --zone {zone}`
	- Add SSH key to project metadata: `gcloud compute project-info add-metadata --metadata-from-file ssh-keys=/tmp/root.pub`
	- SSH: `gcloud compute ssh {account}@{instance} --zone {zone}`

**Privesc Resources**
- [RhinoSec Part 1](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/)
- [RhinoSec Part 2](https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/)
- Tools: [gcploit](https://github.com/dxa4481/gcploit), [GCP-IAM-Privilege-Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation), [GCPHound](https://desi-jarvis.medium.com/gcphound-a-swiss-army-knife-offensive-toolkit-for-google-cloud-platform-gcp-fb9e18b959b4)

## Kubernetes

**What is Kubernetes?**
- Architecture
	- Container orchestration platform that automates deploying, scaling, and managing containers across a cluster of machines
	- A cluster has a control plane (API server, scheduler, etcd) and worker nodes (where pods run)
	- The API server is the single point of entry for all cluster operations, everything goes through it
	- etcd is the backing key-value store for all cluster data; if you can read etcd, you own the cluster
- Core concepts
	- Pods are the smallest deployable unit, containing one or more containers that share networking and storage
	- Namespaces are virtual clusters within a physical cluster, used to segregate resources
	- ConfigMaps and Secrets store configuration data and sensitive values (Secrets are just base64 encoded, not encrypted at rest by default)
- Networking
	- Services expose pods to the network (ClusterIP for internal, NodePort/LoadBalancer for external)
	- Ingress manages external HTTP/HTTPS access to services
- Access control
	- RBAC controls who can do what: Roles define permissions, RoleBindings assign them to users/service accounts

**Commands**
- Enumeration
	- `kubectl get namespaces`
	- `kubectl get pods --all-namespaces`
	- `kubectl get pods -n {namespace}`
	- `kubectl -n {namespace} get svc` to list all services (IPs and ports)
- Interaction
	- `kubectl exec --stdin --tty -n {namespace} {pod_name} -- /bin/bash`
	- If a pod doesn't have `tar` for `kubectl cp`: `cat {local_file} | kubectl exec -i {pod} -n {namespace} -- tee /tmp/{file} >/dev/null`
- Permissions
	- `kubectl auth can-i --list` to list your permissions in the current namespace
		- `kubectl auth can-i {verb} {resource} --namespace {namespace}` for specific checks
- Get sample YAML: `kubectl create deployment my-deployment --image=nginx --dry-run=client -o yaml`

**Service Account Tokens**
- Default location: `/var/run/secrets/kubernetes.io/serviceaccount/token`
- If `kubectl` isn't installed, talk to the API directly:

```sh
APISERVER=https://kubernetes.default.svc
SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount
NAMESPACE=$(cat ${SERVICEACCOUNT}/namespace)
TOKEN=$(cat ${SERVICEACCOUNT}/token)
CACERT=${SERVICEACCOUNT}/ca.crt
curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api
```

**RBAC**
- Roles are namespace-scoped, ClusterRoles are cluster-wide
	- RoleBindings and ClusterRoleBindings determine which users/service accounts can use which roles
- Secret access quirks
	- On older clusters (pre-1.14), `list` on secrets exposed full `data` without `get`. Modern clusters mitigate this, but always verify on target
	- `list` still reveals secret names, useful for targeted `get` attempts

**Privilege Escalation**
1. List secrets and steal tokens for privileged service accounts
	- `kubectl get secrets -n kube-system`
2. Use `create pods/exec` to run commands in pods with privileged service accounts
	- `kubectl exec {pod} -n {namespace} -- cat /var/run/secrets/kubernetes.io/serviceaccount/token`
3. Abuse `bind`, `escalate`, or `impersonate` verbs
4. Create a Bad Pod: mount host filesystem, read all pod filesystems on the node, steal service account tokens
	- May need to bypass admission controllers
5. Use IMDS from within a pod (if exposed) to get node IAM creds, then mint tokens for any service account on that node
	- [Calif blog on EKS privesc](https://blog.calif.io/p/privilege-escalation-in-eks)

**Network Policies**
- Pods are completely open to all traffic until a NetworkPolicy selects them
	- No NetworkPolicies in a namespace means all pods can talk to all other pods (and the internet) freely
	- This is a very common finding, as most clusters don't implement network segmentation

**Admission Controllers**
- Intercept authorized object creation requests to determine if they should be permitted
	- List namespaces without Pod Security enforcement: `kubectl get namespaces --selector='!pod-security.kubernetes.io/enforce'`

**Testing IMDS from a Pod**
- Create a test pod, exec in, then curl the metadata service
- IMDS v1: `curl http://169.254.169.254/latest/meta-data/instance-id`
- IMDS v2 (token required):

```sh
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id
```

**Container Escapes**
- `/proc/sys/kernel/modprobe`: if we can control this path, we can plant a payload, change the modprobe symlink, and trigger a kernel module load
	- Check with `` ls -l `cat /proc/sys/kernel/modprobe` ``
- Tools: [CDK](https://github.com/cdk-team/CDK/wiki), [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- Resources: [HackTricks Docker Breakout](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation/)

**CI/CD to K8s Pivoting**
- If we get code execution on a build/deploy agent running in a K8s cluster:
	1. Steal the pod's service account token
	2. Authenticate to the K8s API
	3. Enumerate permissions with `kubectl auth can-i --list`
	4. Look for privesc paths (secrets access, pod creation, exec into privileged pods)
	5. If no K8s privesc, try lateral movement through the network or cloud IMDS
- Build agent compromise can lead to artifact registry access, which can lead to deploy agent compromise

**GKE Specific**
- Cluster management
	- List clusters: `gcloud container clusters list`
	- Get cluster details: `gcloud container clusters describe {cluster} --zone {zone}`
	- Get kubeconfig: `gcloud container clusters get-credentials {cluster} --zone {zone}`
- List container images: `gcloud container images list`
- [kubeletmein](https://github.com/4ARMED/kubeletmein) for kubelet credential compromise

**EKS Specific**
- Update kubeconfig: `aws eks update-kubeconfig --profile {PROFILE} --name {CLUSTER} --region {REGION}`

**Useful jq Queries**
- Get pod names and IPs with a specific nodeSelector:
	- `cat pods.json | jq '.items[] | select(.spec.nodeSelector.workload == "pci") | [.metadata.name, .status.podIP]'`
- Get all pod IPs:
	- `jq -r '.items[] | select(.status.podIPs != null) | .status.podIPs[].ip' pods.json`
- Include pod names:
	- `jq -r '.items[] | select(.status.podIPs != null) | .metadata.name + ": " + (.status.podIPs[].ip)' pods.json`

## IaC Review

**Terraform**
- HCP Terraform Agents can be shared across workspaces
	- If multiple workspaces share agent pools, compromising one could impact others
	- Agent tokens have the format `{random}.atlasv1.{random}`
	- Recommendation: separate agent pools for sensitive workspaces
