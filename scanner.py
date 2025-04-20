import argparse

from aws import s3
from gcp import storage


def main() -> None:
    '''
    Runs security scans on different AWS services depending on the parameters
    '''
    description = 'Scans cloud resources and provides security report'
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-a', '--aws', action='store_true',
                        help='AWS resources')
    parser.add_argument('-g', '--gcp', action='store_true',
                        help='GCP resources')
    parser.add_argument('-e', '--encryption',
                        action='store_true', help='Scan encryption settings')
    parser.add_argument('-p', '--public', action='store_true',
                        help='Scan public access settings')
    parser.add_argument('--json', action='store_true', help='Output in json')
    args = parser.parse_args()

    if args.aws:
        s3.evaluate_s3_security(enc=args.encryption,
                                pub=args.public, json=args.json)
    elif args.gcp:
        storage.evaluate_storage_security(
            enc=args.encryption, pub=args.public, json=args.json)
    else:
        print('Choose at least one cloud provider.')


if __name__ == '__main__':
    main()
