import json
import requests
import base64
import boto3
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    print(event)
    try:
        request_body = event['body']
        request_json = json.loads(request_body)

        type = request_json['type']

        lambda_functions_dic = {
            'EMAIL': send_email,
            'SMS': send_sms,
            'WHATSAPP': send_whatsapp,
            'JIRA': create_jira_task,
            'TRELLO': create_card_trello
        }

        type_function = lambda_functions_dic.get(type)

        if type_function:
            type_function(request_json) 
        
            return {
                'statusCode': 200
            }
        return {
            'statusCode': 404,
            'body': {
                'messages': f'Type Not Found :{type}'
            }
        }
    
    except Exception as e:
        print(e)
        return {
            'statusCode': 400,
            'body': {
                'messages': str(e)
                
            } 
        }

def send_email(request_json):
    
    secret_response = get_aws_keys()
    
    access_key = secret_response['access_key']
    secret_key = secret_response['secret_key']
    
    from_address = request_json['from']
    to_addresses = request_json['to']
    subject = request_json['subject']
    content = request_json['content']


    client = boto3.client('ses',
                          region_name='us-east-1',
                          aws_access_key_id=access_key,
                          aws_secret_access_key=secret_key)
    utf = 'UTF-8'
    request = {
        'Destination': {
            'ToAddresses': to_addresses
        },
        'Message': {
            'Body': {
                'Text': {
                    'Charset': utf,
                    'Data': content
                }
            },
            'Subject': {
                'Charset': utf,
                'Data': subject
            }
        },
        'Source': from_address
    }
    client.send_email(**request)
    print('Email sent successfully')

def send_whatsapp(request_json):
    
    secret_response = get_zenvia_keys()
    
    token = secret_response['token']
    account = secret_response['account']

    to_numbers = request_json['to']
    content = request_json['content']
    url = 'https://api.zenvia.com/v2/channels/whatsapp/messages'


    headers = {
        'X-API-TOKEN': token,
        'Content-Type': 'application/json'
    }

    body = {
        'from': account,
        'contents': [{'type': 'text', 'text': content}]
    }
    
    for number in to_numbers:
        body['to'] = number
        requests.post(url, headers=headers, json=body)
        
def send_sms(request_json):
    
    secret_response = get_zenvia_keys()
    
    token = secret_response['token']
    account = secret_response['account']
    
    to_numbers = request_json['to']
    content = request_json['content']

    url = "https://api.zenvia.com/v2/channels/sms/messages"

    
    headers = {
        "X-API-TOKEN": token,
        "Content-Type": "application/json"
    }

    body = {
        "from": account,
        "contents": [{"type": "text", "text": content}]
    }

    
    for number in to_numbers:
        body["to"] = number
        requests.post(url, headers=headers, json=body)

def create_jira_task(request_json):
    
    secret_name = request_json['secretsName']
    summary = request_json['summary']
    description = request_json['description']
    issue_type = request_json['issueType']
    
    secrets_response = get_jira_secrets(secret_name)

    email = secrets_response['email']
    token = secrets_response['token']
    project_key = secrets_response['projectKey']
    
    url = 'https://giullianomassarelli.atlassian.net/rest/api/2/issue'

    email_and_token = f"{email}:{token}"
    cript64_auth = base64.b64encode(email_and_token.encode('utf-8')).decode('utf-8')

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + cript64_auth
    }

    payload = {
        'fields': {
            'project': {
                'key': project_key
            },
            'summary': summary,
            'description': description,
            'issuetype': {
                'name': issue_type
            }
        }
    }

    response = requests.post(url, headers=headers, data=json.dumps(payload))
    
    if response.status_code != 201:
        response_json = response.json()
        error_message = response_json['errors']['project'] 
        raise Exception(error_message)
        
def create_card_trello(request_json):
    
    name = request_json['name']
   
    desc = request_json['desc']
    
    url = "https://api.trello.com/1/cards"
    secret_name = request_json['secretsName']
    
    
    secrets_response = get_trello_secrets(secret_name)
    
    id_list = secrets_response['idList']
    key = secrets_response['key']
    token = secrets_response['token']
    
    query_params = {
        'idList': id_list,
        'key': key,
        'token': token,
        'name': name,
        'desc': desc
    }
    
    response = requests.post(url, params=query_params)
    
    if response.status_code != 200:
        raise Exception(f'a error occurent when trying create a card in trello, message error: {response.text}')

def get_aws_keys(secret_name):
    
    region = 'us-east-1'
    
    session = boto3.session.Session()
    client = session.client(
        service_name= 'secretsmanager',
        region_name=region
    )
    
    try:
        secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as error:
        print(error)
    else:
        if 'SecretString' in secret_value_response:
            secret = json.loads(secret_value_response['SecretString'])
            return secret
        else:
            decoded_binary_secret = base64.b64decode(secret_value_response['SecretBinary'])

def get_zenvia_keys(secret_name):

    region = 'us-east-1'
    
    session = boto3.session.Session()
    client = session.client(
        service_name= 'secretsmanager',
        region_name=region
    )
    
    try:
        secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as error:
        print(error)
    else:
        if 'SecretString' in secret_value_response:
            secret = json.loads(secret_value_response['SecretString'])
            return secret
        else:
            decoded_binary_secret = base64.b64decode(secret_value_response['SecretBinary'])

def get_trello_secrets(secret_name):
    region = 'us-east-1'
    
    session = boto3.session.Session()
    client = session.client(
        service_name= 'secretsmanager',
        region_name=region
    )
    
    try:
        secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as error:
        print(error)
    else:
        if 'SecretString' in secret_value_response:
            secret = json.loads(secret_value_response['SecretString'])
            return secret
        else:
            decoded_binary_secret = base64.b64decode(secret_value_response['SecretBinary'])
            return decoded_binary_secret
            
def get_jira_secrets(secret_name):
    
    region = 'us-east-1'
    
    session = boto3.session.Session()
    client = session.client(
        service_name= 'secretsmanager',
        region_name=region
    )
    
    try:
        secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as error:
        print(error)
    else:
        if 'SecretString' in secret_value_response:
            secret = json.loads(secret_value_response['SecretString'])
            return secret
        else:
            decoded_binary_secret = base64.b64decode(secret_value_response['SecretBinary'])
            return decoded_binary_secret

if __name__ == "__main__":
    secret_name = "your secret manager name"
    #get_aws_keys(secret_name)
    