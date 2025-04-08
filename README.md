# Cloud Security Scanner
This tool allows to check configuration settings of cloud resources and provides report on security status.

## Current status
Implemented encryption modules for AWS S3 and GCP storage.

## How to use
Recommended to create a virtualenv. Inside venv run `pip install -r requirements-<module>.txt` and then the scanner can be run as `python3 scanner.py -a/-g -e`, where
`-a`: AWS
`-g`: GCP
`-e`: encryption
