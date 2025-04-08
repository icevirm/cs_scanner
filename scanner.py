import argparse

from aws import s3
from gcp import storage

def main() -> None:
    '''
    Runs security scans on different AWS services depending on the parameters
    '''
    description = 'Scans cloud resources and provides security report'
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-a', '--aws', action='store_true', help='AWS resources')
    parser.add_argument('-g', '--gcp', action='store_true', help='GCP resources')
    parser.add_argument('-e', '--encryption', action='store_true', help='Scan encryption settings')
    parser.add_argument('-p', '--public', action='store_true', help='Scan public access settings')
    args = parser.parse_args()

    if args.aws:
        if args.encryption and args.public:
            s3.evaluate_s3_security(enc=True, pub=True)
        elif args.encryption:
            s3.evaluate_s3_security(enc=True, pub=False)
        elif args.public:
            s3.evaluate_s3_security(enc=False, pub=True)
        else:
            s3.evaluate_s3_security(enc=False, pub=False)
    elif args.gcp:
        if args.encryption:
            storage.evaluate_storage_security(enc=True)
        else:
            storage.evaluate_storage_security(enc=False)
    else:
        print('Choose at least one cloud provider.')


if __name__ == '__main__':
    main()
