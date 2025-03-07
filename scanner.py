from aws import s3

def main() -> None:
    '''
    Runs security scans on different AWS services depending on the parameters
    '''
    s3.evaluate_s3_security()


if __name__ == '__main__':
    main()
