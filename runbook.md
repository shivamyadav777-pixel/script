h1. Vault AMI Post-Upgrade Validation Runbook

h2. Purpose
This runbook is used to validate HashiCorp Vault health after an AMI upgrade. It is intended for teams that access Vault through a Dojo environment and want a repeatable validation process with reusable evidence for managers, change records, and support teams.

h2. Scope
This runbook applies to Vault environments such as le1, xe1, and pe1, including both primary and DR clusters.

h2. Execution Model
Validation should be run from the approved Dojo environment for the target Vault cluster, not directly from a local laptop unless your team explicitly allows that.

h2. Objectives
After the AMI upgrade, validate that:
* Secret read/write works from Vault CLI and, if required, UI
* Replication between primary and secondary/DR is healthy
* All primary and DR nodes are unsealed
* Raft peer membership is correct
* Raft snapshots are being generated correctly
* A daily maintenance pipeline can run successfully
* Validation evidence is captured in a report

h2. Prerequisites
Before starting, confirm the following:
* Access to the correct Dojo for the target environment
* VPN or network access required for Dojo access
* vault CLI is available inside Dojo
* aws CLI is available inside Dojo
* Python is available inside Dojo if the automation script will be used
* Access from Dojo to:
** Vault primary cluster
** Vault DR cluster
** S3 snapshot bucket
** Concourse, if pipeline validation is included
* Valid Vault authentication method inside Dojo
* Valid AWS authentication or role access inside Dojo
* Approved test secret path, such as kvtest/test
* Confirmed list of primary and DR nodes
* Confirmed S3 bucket names and prefixes
* Confirmed Concourse pipeline names
* Team-approved replication validation command or runbook reference

h2. Information To Collect Before Starting
* Target environment: le1, xe1, or pe1
* Dojo name or access path for that environment
* Primary Vault address
* DR Vault address
* Primary node list
* DR node list
* Snapshot bucket name
* Snapshot prefix, usually raft-snapshots/
* Replication validation command
* Maintenance pipeline names
* AMI upgrade completion timestamp, if snapshot freshness must be compared against it

h2. Safety Guidelines
* Perform first automation tests in non-production
* Use only an approved test path
* Use a unique temporary test key
* Do not overwrite existing application secrets
* Prefer read-only commands wherever possible
* Keep pipeline-trigger actions disabled until approved
* If any critical validation fails, stop and escalate

h2. High-Level Flow
# Connect to the correct Dojo
# Confirm tools and access
# Authenticate to Vault
# Run validation steps
# Capture evidence
# Save or send report
# Share results with manager or attach to change record

h2. Detailed Procedure

h3. 1. Connect To Dojo
Open the approved Dojo for the target environment.

Verify you are in the correct Dojo before running any commands.

{code:bash}
hostname
whoami
env | grep VAULT
{code}

Expected result:
* You are connected to the intended Dojo
* Environment variables and network path match the target Vault environment

h3. 2. Verify Required Tools
Check that the required tools are available inside Dojo.

{code:bash}
vault --version
aws --version
python --version
{code}

If Concourse automation is planned, also verify:

{code:bash}
fly --version
{code}

Expected result:
* Commands complete successfully
* Supported versions are available

h3. 3. Authenticate To Vault
Authenticate inside Dojo using the team-approved method.

{code:bash}
vault login
{code}

Validate the token:

{code:bash}
vault token lookup
{code}

Expected result:
* Login succeeds
* Token is valid
* Token has the required access for validation tasks

h3. 4. Confirm Target Environment
Verify that the correct Vault address is in use.

{code:bash}
echo $VAULT_ADDR
{code}

If needed, set it explicitly:

{code:bash}
export VAULT_ADDR=https://vault-le1-primary.example.com
{code}

Expected result:
* VAULT_ADDR points to the correct primary cluster for the target environment

h3. 5. Secret Read/Write Validation
Use an approved non-business secret path such as kvtest/test.

Write a temporary unique key:

{code:bash}
vault kv put kvtest/test ami_validation_<timestamp>=ok
{code}

Read back the secret:

{code:bash}
vault kv get kvtest/test
{code}

Expected result:
* Write succeeds
* Newly written validation key is visible and readable

Notes:
* Use a unique timestamp-based key
* Do not overwrite existing business data
* If required by policy, clean up the key afterward

h3. 6. Vault UI Validation
If UI validation is part of the team standard process:
* Log in to Vault UI for the target environment
* Navigate to the approved test path
* Verify that the secret can be viewed
* If policy allows, create and save a temporary secret through the UI as an additional test

Expected result:
* UI access works
* Read/write behavior matches CLI validation

h3. 7. Replication Health Validation
Run the team-approved replication validation command.

Example placeholder:

{code:bash}
vault read -format=json sys/replication/status
{code}

Replace this with the exact internal runbook command if different.

Expected result:
* Replication is healthy according to team standard
* Primary and secondary/DR relationship is intact
* No unexpected lag or broken state is reported

Evidence to capture:
* Command used
* Output or summary result
* Screenshot if the team uses UI-based validation

h3. 8. Node Unseal Validation
Confirm that all primary and DR EC2 nodes are unsealed.

UI method
* Open Vault UI
* Go to Status
* In the Server section, confirm that Unsealed is green for all nodes

API or automation method
Query each node’s health endpoint:

https://<node>:8200/v1/sys/health

Expected result:
* Every primary node shows sealed=false
* Every DR node shows sealed=false

Notes:
* Standby nodes are acceptable as long as they are unsealed
* If any node is sealed, treat it as a validation failure

h3. 9. Raft Peer Validation
Run peer validation for both primary and DR clusters.

{code:bash}
vault operator raft list-peers -format=json
{code}

Expected result for each cluster:
* Total peers = 5
* 1 leader
* 4 followers

Validation must be performed separately for:
* Primary cluster
* DR cluster

If results differ from expected:
* Stop validation
* Capture output
* Escalate to Vault or platform support

h3. 10. Snapshot Validation In Vault
Validate automatic raft snapshot configuration and status.

{code:bash}
vault read sys/storage/raft/snapshot-auto/status/s3
vault read sys/storage/raft/snapshot-auto/config/s3
{code}

Expected result:
* Snapshot auto configuration exists
* Status is healthy
* No errors indicate snapshot failures

Evidence to capture:
* Snapshot status output
* Snapshot config output

h3. 11. Snapshot Validation In S3
Validate the latest snapshot object in the appropriate S3 bucket.

{code:bash}
aws s3api list-objects-v2 --bucket <bucket-name> --prefix raft-snapshots/
{code}

Expected result:
* Objects exist under the expected prefix
* Latest snapshot timestamp is current and consistent with post-upgrade expectations

Typical bucket naming pattern:
* vault-inc-primary-raft-snapshots
* vault-nprd-primary-raft-snapshots
* vault-prod-primary-raft-snapshots

Evidence to capture:
* Bucket name
* Latest snapshot object key
* Last modified timestamp

h3. 12. Daily Maintenance Pipeline Validation
In the relevant environment, select a daily maintenance pipeline.

Example:
* check certificate pipeline in Concourse

Recommended phase-1 approach:
* Choose a pipeline manually or from an approved shortlist
* Trigger only after approval
* Confirm full success

Expected result:
* Job starts successfully
* All steps pass
* Job completes green

Evidence to capture:
* Pipeline name
* Run ID or build number
* Final status
* Screenshot or CLI output

h3. 13. Optional Automation Execution
If using the Python automation from inside Dojo:

{code:bash}
python vault_ami_validation.py --env le1
{code}

With explicit token:

{code:bash}
python vault_ami_validation.py --env le1 --vault-token <token>
{code}

With HTML report and optional email:

{code:bash}
python vault_ami_validation.py --env le1 --smtp-host <smtp-host> --smtp-port 25 --email-from <sender-email> --email-to <recipient1> <recipient2>
{code}

Expected outputs:
* Console summary
* JSON report
* HTML report
* Optional email with HTML attachment

h2. Pass Criteria
Validation is successful only when:
* Vault authentication is valid
* Secret read/write passes
* Replication is healthy
* All primary nodes are unsealed
* All DR nodes are unsealed
* Primary raft peer count is correct
* DR raft peer count is correct
* Snapshot auto status is healthy
* Latest S3 snapshot is present and recent
* Maintenance pipeline completes successfully

h2. Failure Criteria
Validation is failed if any of the following occur:
* Vault login fails
* Secret write/read fails
* Replication is unhealthy
* Any primary or DR node is sealed
* Raft peer count is incorrect
* Leader or follower count is incorrect
* Snapshot status shows error
* Latest snapshot is missing or stale
* Maintenance pipeline fails

h2. Failure Handling
If any critical validation fails:
* Stop further approval steps
* Capture the exact failing command and output
* Take screenshots if validation was UI-based
* Inform the Vault or platform support team
* Do not mark the AMI change as validated
* Attach evidence to the incident, ticket, or change record

h2. Evidence To Capture
For each validation run, capture:
* Environment name
* Dojo used
* Validation date and time
* Operator name
* Test secret path
* Temporary test key name
* Replication output
* Node unseal status
* Raft peer output
* Snapshot status output
* Latest S3 snapshot timestamp
* Maintenance pipeline result
* Generated HTML or JSON report
* Screenshots if UI was used

h2. Manager Demo Plan
For showing this process to a manager:
# Use a non-production environment such as le1
# Run from the approved Dojo
# Keep risky or team-specific actions minimal
# Use a temporary test key in the approved test path
# Show that most checks are read-only
# Open the generated HTML report after the run
# Explain what is automated and what remains manual
# Highlight:
## Less manual effort
## Consistent validation
## Reusable evidence
## Lower chance of missed checks

h2. Recommended Demo Message
{quote}
This validation runs from the approved Dojo, uses read-only checks for most steps, and performs only one controlled temporary secret write in an approved test path. It produces a clean report that can be reused for audit and change validation.
{quote}

h2. Open Questions To Confirm With Team
* Which Dojo should be used for each environment?
* Are vault, aws, and python available in every Dojo?
* Is fly available if Concourse will be automated?
* Is kvtest/test approved in all environments?
* Should the temporary validation key be deleted after the run?
* What exact replication command should be treated as the source of truth?
* What are the exact node health endpoints?
* What AWS profile and region should be used in each Dojo?
* Which maintenance pipelines are approved for validation?
* Is email relay allowed from Dojo for sending reports?

h2. Ownership
Recommended owners:
* Vault or platform team for technical validation logic
* Change owner for execution during AMI upgrade
* Team lead or manager for signoff on report format and evidence expectations
