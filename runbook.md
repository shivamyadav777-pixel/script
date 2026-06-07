vault-ami-validation/
├── vault_ami_validation.py
├── vault_validation_config.json
├── inputs/
│   ├── le1/
│   │   ├── primary-token
│   │   ├── dr-token
│   │   └── aws-keys
│   ├── xe1/
│   │   ├── primary-token
│   │   ├── dr-token
│   │   └── aws-keys
│   └── pe1/
│       ├── primary-token
│       ├── dr-token
│       └── aws-keys
└── reports/
    ├── le1/
    ├── xe1/
    └── pe1/




aws-keys example:

AWS_ACCESS_KEY_ID=xxxx
AWS_SECRET_ACCESS_KEY=yyyy
AWS_SESSION_TOKEN=zzzz
AWS_DEFAULT_REGION=us-east-1


Run instructions
1. Go to the Dojo or approved execution environment.

2. Create this folder structure:

vault-ami-validation/
├── vault_ami_validation.py
├── vault_validation_config.json
├── inputs/
│   ├── le1/
│   │   ├── primary-token
│   │   ├── dr-token
│   │   └── aws-keys
│   ├── xe1/
│   │   ├── primary-token
│   │   ├── dr-token
│   │   └── aws-keys
│   └── pe1/
│       ├── primary-token
│       ├── dr-token
│       └── aws-keys
└── reports/
    ├── le1/
    ├── xe1/
    └── pe1/

3. Place the Python script here:
vault-ami-validation/vault_ami_validation.py

4. Place the config here:
vault-ami-validation/vault_validation_config.json

5. Add input files for the environment you want to run.

Example for le1:
vault-ami-validation/inputs/le1/primary-token
vault-ami-validation/inputs/le1/dr-token
vault-ami-validation/inputs/le1/aws-keys

6. Put the Vault token values into:
primary-token
dr-token

Each file should contain only the token value.

7. Put AWS credentials into:
aws-keys

Example:
AWS_ACCESS_KEY_ID=xxxx
AWS_SECRET_ACCESS_KEY=yyyy
AWS_SESSION_TOKEN=zzzz
AWS_DEFAULT_REGION=us-east-1

8. Update vault_validation_config.json with real values:
- primary vault address
- DR vault address
- snapshot bucket
- snapshot prefix
- aws region
- maintenance pipeline names
- snapshot retry settings if needed

9. Make sure these commands work in the Dojo:
vault --version
aws --version
python --version

10. Go to the project folder:

cd vault-ami-validation

11. Run the script:

python vault_ami_validation.py

12. When prompted, enter the environment name only.

Example:
le1

13. The script will automatically read:
inputs/le1/primary-token
inputs/le1/dr-token
inputs/le1/aws-keys

14. The script will run all checks.
If one normal validation check fails, the remaining checks will still continue.
It stops only for critical setup failures like:
- missing config
- missing token files
- missing aws-keys
- invalid environment name

15. Output files will be generated automatically in:

reports/le1/

Example output:
reports/le1/vault_validation_report_le1_20260607153000.json
reports/le1/vault_validation_report_le1_20260607153000.html

16. Open the HTML report and share it with your manager or upper management.

17. For another environment, add the correct files under:
inputs/xe1/
or
inputs/pe1/

Then run the script again and enter:
xe1
or
pe1


