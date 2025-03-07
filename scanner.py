from s3 import evaluate_s3_security

def main() -> None:
    '''
    Runs security scans on different AWS services depending on the parameters
    '''
    evaluate_s3_security()


if __name__ == '__main__':
    main()
