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

import aws
import gcp


def main() -> None:
    '''
        This is the main module - to call security evaluations for different
        services and configurations.

        Supported parameters:
        # Cloud Service Provider
        --aws, -a: Scan AWS resources
        --gcp, -g: Scan Google Cloud resources

        # Cloud service
        --storage, -s: Scan storage resources, such as S3 in AWS
                       or Cloud Storage in GCP

        # Configuration
        --encryption, -e: Scan encryption settings
        --public, -p: Scan public access settings

        # Output
        --json: Output in JSON, otherwise in table format
    '''
    description = 'Scans cloud resources and provides security report'
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-a', '--aws', action='store_true',
                        help='AWS resources')
    parser.add_argument('-g', '--gcp', action='store_true',
                        help='GCP resources')
    parser.add_argument('-s', '--storage',
                        action='store_true', help='Storage service')
    parser.add_argument('-e', '--encryption',
                        action='store_true', help='Scan encryption settings')
    parser.add_argument('-p', '--public', action='store_true',
                        help='Scan public access settings')
    parser.add_argument('--json', action='store_true', help='Output in json')
    args = parser.parse_args()

    if args.aws:
        if args.storage:
            aws.s3.evaluate_s3_security(enc=args.encryption,
                                        pub=args.public, json=args.json)
        else:
            print('Choose at least one service.')
    elif args.gcp:
        if args.storage:
            gcp.storage.evaluate_storage_security(
                enc=args.encryption, pub=args.public, json=args.json)
        else:
            print('Choose at least one service.')
    else:
        print('Choose at least one cloud provider.')


if __name__ == '__main__':
    main()
