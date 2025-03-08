import argparse

from aws import s3

def main() -> None:
    '''
    Runs security scans on different AWS services depending on the parameters
    '''
    description = 'Scans cloud resources and provides security report'
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-a', '--aws', action='store_true', help='AWS resources')
    parser.add_argument('-e', '--encryption', action='store_true', help='Scan encryption settings')
    args = parser.parse_args()

    if args.aws:
        if args.encryption:
            s3.evaluate_s3_security(enc=True)
        else:
            s3.evaluate_s3_security(enc=False)
    else:
        print('Choose at least one cloud provider.')


if __name__ == '__main__':
    main()
