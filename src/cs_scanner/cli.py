'''
    This tool scans cloud services' configuration settings to
    evaluate cloud security posture.

    It supports AWS, GCP and Azure public cloud service providers.

    The scanner supports multiple command line arguments, which define
    what modules will be launched.

    The main focus of scanning is to indicate problematic misconfigured
    services which can pose a security risk. The tool itself does not 
    evaluate the risk, it should be used in alignment with existing
    threat model.
'''
import argparse

from cs_scanner import aws
from cs_scanner import gcp

SUPPORTED_SERVICES_AWS = ['s3']
SUPPORTED_SERVICES_GCP = ['storage']


def main() -> None:
    '''
        This is the main module - to call security evaluations for different
        services and configurations.
    '''
    description = 'This tool scans cloud resources and provides security report'
    parser = argparse.ArgumentParser(description=description)

    provider = parser.add_argument_group("Cloud provider")
    provider.add_argument('provider', choices=['aws', 'gcp'], default='aws', help='Cloud provider')

    services = parser.add_argument_group("Services")
    services.add_argument('service', help='Cloud service')
    
    configurations = parser.add_argument_group("Configurations")
    configurations.add_argument('-e', '--encryption',
                        action='store_true', help='Scan encryption settings')
    configurations.add_argument('-p', '--public', action='store_true',
                        help='Scan public access settings')
    
    output = parser.add_argument_group("Output")
    output.add_argument('--json', action='store_true', help='Output in JSON')
    
    args = parser.parse_args()

    if not (args.encryption or args.public):
        args.encryption = args.public = True

    if args.provider == 'aws':
        if args.service == 's3':
            aws.s3.evaluate_s3_security(enc=args.encryption,
                                        pub=args.public, json=args.json)
        else:
            print(f'Service {args.service} is not supported.')
            print(f'Supported services: {", ".join(SUPPORTED_SERVICES_AWS)}')
    elif args.provider == 'gcp':
        if args.service == 'storage':
            gcp.storage.evaluate_storage_security(
                enc=args.encryption, pub=args.public, json=args.json)
        else:
            print(f'Service {args.service} is not supported.')
            print(f'Supported services: {", ".join(SUPPORTED_SERVICES_GCP)}')
