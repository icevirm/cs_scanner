'''
    This modules scans configuration settings of Azure Storage Accounts
    in the given subscription.

'''

from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from json import dumps
import pandas as pd


def create_storage_mgmt_client(credential, subscription_id):
    '''
        Creates client to do further API calls for Storage Accounts
    '''
    return StorageManagementClient(credential, subscription_id)

def get_all_storage_accounts_in_subscription(storage_client):
    '''
        Creates Iterable of all Storage Accounts in given subscription
    '''
    return storage_client.storage_accounts.list()

def check_encryption(storage_account) -> dict:
    '''
        Gather information about Storage Account encryption settings

        Args: (str) storage_account - StorageAccount object from Azure SDK
        Returns: (dict) - status of encryption settings
    '''
    encryption_status = {
        'EncryptionKeySource': storage_account.encryption.key_source,
        'InfrastructureEncryptionEnabled': storage_account.encryption.require_infrastructure_encryption,
        'Services': {
            'Blob': 'N/A',
            'File': 'N/A',
            'Table': 'N/A',
            'Queue': 'N/A'
        },
        'AllowHTTPSOnly': storage_account.enable_https_traffic_only,
        'MinimumTLS': storage_account.minimum_tls_version
    }

    if storage_account.encryption.services.blob:
        encryption_status['Services']['Blob'] = storage_account.encryption.services.blob.enabled

    if storage_account.encryption.services.file:
        encryption_status['Services']['File'] = storage_account.encryption.services.file.enabled

    if storage_account.encryption.services.table:
        encryption_status['Services']['Table'] = storage_account.encryption.services.table.enabled

    if storage_account.encryption.services.queue:
        encryption_status['Services']['Queue'] = storage_account.encryption.services.queue.enabled
    
    return encryption_status

def check_public_access(storage_account) -> dict:
    '''
        Gather information about Storage Account Public Access settings

        Args: (str) storage_account - StorageAccount object from Azure SDK
        Returns: (dict) - status of public access settings
    '''
    public_status = {
        'PublicNetworkAccess': storage_account.public_network_access,
        'BlobPublicAccess': storage_account.allow_blob_public_access,
        'DefaultFirewallAction': storage_account.network_rule_set.default_action
    }
    return public_status

def evaluate(storage_accounts: list, enc: bool, pub: bool) -> list:
    '''
        Function that takes list of all storage accounts and goes through all
        individual check functions for different settings.

        Args: (list) storage_accounts - list of StorageAccount objects from Azure SDK
              (bool) enc - encryption module
              (bool) pub - public access module

        Returns: (list)evaluations - status of all executed checks
    '''
    evaluations = []
    for storage in storage_accounts:

        storage_account_evaluation = {
        'StorageAccountName': storage.name,
        'Encryption': {},
        'PublicAccess': {}
        }
        
        if enc:
            storage_account_evaluation['Encryption'] = check_encryption(storage)
        if pub:
            storage_account_evaluation['PublicAccess'] = check_public_access(storage)

        evaluations.append(storage_account_evaluation)
    
    return evaluations

# Output
def output_json(evaluations: list) -> None:
    '''
        Outputs the result in JSON, useful for automation

        Args: (list) evaluations - outcome of evaluations function
        Returns: None
    '''
    print(dumps(evaluations))

def output_table(evaluations: list) -> None:
    '''
        Outputs the result in a Pandas Dataframe, which looks like a table

        Args: (list) evaluations - outcome of evaluations function
        Returns: None
    '''
    pd.set_option('display.max_columns', None)
    table = pd.json_normalize(evaluations).melt(var_name='Setting')
    print(table)


# def evaluate_storage_security(sub, enc: bool, pub: bool, json: bool) -> None:
def evaluate_storage_security(sub, enc: bool, pub: bool, json: bool) -> None:
    '''
        Runs different security checks on Azure Storage accounts in the subscription and reports the results

        Args:
            (bool) enc - scan encryption settings
            (bool) pub - scan public access settings
            (bool) json - output in JSON format
        Returns: None
    '''
    #TODO:centralize how to aquire login tokens/credentials
    credential = DefaultAzureCredential()
    client = create_storage_mgmt_client(credential, sub)
    storage_accounts = get_all_storage_accounts_in_subscription(client)
    evaluations = evaluate(storage_accounts, enc, pub)

    if json:
        output_json(evaluations)
    else:
        output_table(evaluations)
