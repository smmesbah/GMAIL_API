import flask
from flask import request
import os
import requests
import base64
import json
import csv

from dotenv import load_dotenv
from openai import OpenAI

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from helpers import credentials_to_dict, print_index_table, save_credentials_to_json, load_credentials_from_json

CLIENT_SECRETS_FILE = "credentials.json"

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
API_SERVICE_NAME = "gmail"
API_VERSION = "v1"

load_dotenv()
app = flask.Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

@app.route("/")
def index():
    return "Hello, World!"

# POST Request that classifies tasks into categories, examples are provided in task_examples.csv
@app.route("/classify_task", methods=["POST"])
def task_classifier():
    api_key = os.getenv("OPENAI_API_KEY")
    client = OpenAI(api_key=api_key)

    examples = []
    with open('task_examples.csv', 'r', newline='', encoding='utf-8') as file:
        csv_reader = csv.reader(file, delimiter=',', quotechar='"')
        next(csv_reader)  # Skip the header row
        for row in csv_reader:
            if len(row) >= 2:  # Ensure we have at least 2 columns
                task_description = row[0]
                output_format = ','.join(row[1:])  # Join all remaining columns
                examples.append({"role": "user", "content": f"Example of the task description: {task_description}"})
                examples.append({"role": "assistant", "content": output_format})
            else:
                print(f"Skipping invalid row: {row}")

    # Construct messages list
    messages = [
        {
            "role": "system",
            "content": 
                "You are a task classifier. You are given a task description and you need to classify the task into one of the following categories: send_email, set_reminder, call_person, send_message, set_reminder, submit_proposal, follow_up_email, send_message_to_person, send_message_to_person_at_time, submit_proposal_at_time" +
                "DO NOT USE ANYTHING OTHER THAN THE CATEGORIES LISTED. ONLY RETURN THE CATEGORY NAME EXACTLY AS SHOWN." +
                "Strictly follow the format of the examples given."
        },
    ]
    # Add examples from CSV
    messages.extend(examples)

    data = request.get_json()
    task_description = data.get("task_description", "")

    # Add the final user message
    messages.append({"role": "user", "content": "Now, output a following the the format of the examples above from this task description: " + task_description})

    response = client.chat.completions.create(
    model="gpt-4o-2024-08-06",
    messages=messages
    )

    print(response.choices[0].message.content)

    response_content = response.choices[0].message.content.split('\n')
    response_content = "[{\'task\': \'send_email\', \'task_title\': \'Send Email to Pankti\', \'task_description\': \'send an email to pankti at 10am asking for a meeting\'}, {\'task\': \'set_reminder\', \'task_title\': \'Set Reminder to Call Pankti\', \'task_description\': \'set a reminder for 1pm to call pankti\'}]"

    # Parse response into a list of JSON objects
    parsed_response = json.loads(response_content.replace("'", '"'))
    print(parsed_response);
    return flask.jsonify(parsed_response)


@app.route("/test")
def test_api_request():
    if 'credentials' not in flask.session:
        return flask.redirect('authorize');
    
    # Load credentials from the session.
    credentials = Credentials(**flask.session['credentials'])

    gmail = build(API_SERVICE_NAME, API_VERSION, credentials=credentials)
    results = gmail.users().labels().list(userId="me").execute()

    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.jsonify(**results)

@app.route('/authorize')
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
    )
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
    )
    flask.session['state'] = state
    return flask.redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = flask.session['state']
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
    )
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)

    save_credentials_to_json(credentials)

    return flask.redirect(flask.url_for('test_api_request'))

@app.route('/revoke')
def revoke():
    if 'credentials' not in flask.session:
        return ('You need to <a href="/authorize">authorize</a> before ' 'testing the code to revoke credentials.')

    credentials = Credentials(**flask.session['credentials'])

    revoke = requests.post('https://oauth2.googleapis.com/revoke',
                           params={'token': credentials.token},
                           headers={'content-type': 'application/x-www-form-urlencoded'})
    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return 'Credentials successfully revoked.'
    else:
        return('An error occurred.' + print_index_table())
    
@app.route('/clear')
def clear_credentials():
    if 'credentials' in flask.session:
        del flask.session['credentials']
    return ('Credentials have been cleared.<br><br>' +
          print_index_table())

# GET Request to list messages
@app.route('/list_messages')
def list_messages():
    # Load credentials from JSON file
    # credentials = load_credentials_from_json()

    # if credentials is None:
    #     return flask.redirect('authorize')
    if 'credentials' not in flask.session:
        return flask.redirect('authorize');

    # Load credentials from the session.
    credentials = Credentials(**flask.session['credentials'])
    
    # Build Gmail service
    gmail = build(API_SERVICE_NAME, API_VERSION, credentials=credentials)
    
    # Fetch messages
    results = gmail.users().messages().list(userId="me").execute()

    # Update session with latest credentials (optional)
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.jsonify(**results)

@app.route('/sent_emails/<target_email>')
def sent_emails(target_email):
    try:
        if 'credentials' not in flask.session:
            return flask.redirect('authorize')
        
        credentials = Credentials(**flask.session['credentials'])
        gmail = build(API_SERVICE_NAME, API_VERSION, credentials=credentials)
        
        # Query for sent emails to the target_email
        query = f"from:me to:{target_email}"

        messages = gmail.users().messages().list(userId='me', q=query).execute()

        results = []
        
        for message in messages.get('messages', []):
            msg = gmail.users().messages().get(userId='me', id=message['id'], format='full').execute()
            
            headers = {header['name']: header['value'] for header in msg['payload']['headers']}
            
            
            results.append({
                'From': headers.get('From'),
                'To': headers.get('To'),
                'Subject': headers.get('Subject'),
                'Date': headers.get('Date'),
                'email_body': msg['snippet']
            })
        
        flask.session['credentials'] = credentials_to_dict(credentials)
        
        return flask.jsonify(results)
    
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return flask.jsonify({"error": str(e)}), 500


# generate an email to the target_email
@app.route('/generate_email/<target_email>')
def generate_email(target_email):

    api_key = os.getenv("OPENAI_API_KEY")
    client = OpenAI(api_key=api_key)

    # fetch all the emails sent to the target_email using the sent_emails endpoint
    response = sent_emails(target_email)
    emails = response.get_json()
    
    # Add emails to examples list
    examples = []
    for email in emails[-10:]:
        examples.append({"role": "user", "content": f"Example of {email['From']}'s writing style with the recipient {email['To']}:"})
        examples.append({"role": "assistant", "content": email['email_body']})

    # Construct messages list
    messages = [
        {
            "role": "system",
            "content": 
                f"You are a virtual assistant of {email['From']}. Your task is to generate emails maintaining {email['From']}'s tone and style.\n" +
                f"You are given examples of {email['From']}'s previous messages and a new message from someone. Respond to the message in {email['From']}'s style.\n" +
                f"Do not fix a typo in the message if {email['From']} consistently follows it.\n" +
                f"Strictly follow the style and tone of the previous messages.\n" +
                f"Analyze the previous messages to determine if emojis are used. If emojis are present, maintain a similar frequency and style of emoji usage. If emojis are not used, refrain from using them in your response." + 
                f"Strictly maintain the style in which {email['From']} addresses the recipient."
        },
    ]

    messages.extend(examples)

    # Add the final user message
    messages.append({"role": "user", "content": f"Now, send a follow up message to {target_email} telling them the backend is ready."})

    response = client.chat.completions.create(
        model="gpt-4o-2024-08-06",
        messages=messages
    )

    print(response.choices[0].message.content)
    return flask.jsonify(response.choices[0].message.content)


# GET the labels of the messages
@app.route('/list_labels')
def list_labels():
    # if 'credentials' not in flask.session:
    #     return flask.redirect('authorize');

    # # Load credentials from the session.
    # credentials = Credentials(**flask.session['credentials'])

    # Load credentials from JSON file
    credentials = load_credentials_from_json()

    if credentials is None:
        print("Credentials is None")
        return flask.redirect('authorize')


    # Build gmail service
    gmail = build(API_SERVICE_NAME, API_VERSION, credentials=credentials)

    # Fetch labels
    labels = gmail.users().labels().list(userId="me").execute()

    # Update session with latest credentials (optional)
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.jsonify(**labels)

# GET the messages from a specific label
@app.route('/list_messages_from_label/<label_id>')
def list_messages_from_label(label_id):
    # Load credentials from JSON file
    credentials = load_credentials_from_json()

    if credentials is None:
        return flask.redirect('authorize')

    # Build Gmail service
    gmail = build(API_SERVICE_NAME, API_VERSION, credentials=credentials)

    # Fetch labels
    # labels = gmail.users().labels().list(userId="me").execute()

    # Get the label id of the label "INBOX"
    # for label in labels['labels']:
    #     if label['name'] == 'INBOX':
    #         label_id = label['id']
    #         break

    # Fetch messages from the label "INBOX"
    results = gmail.users().messages().list(userId="me", labelIds=[label_id]).execute()

    # Update session with latest credentials (optional)
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.jsonify(**results)

# GET the message with a specific message id
@app.route('/get_message/<message_id>')
def get_message(message_id):
    # Load credentials from JSON file
    credentials = load_credentials_from_json()

    if credentials is None:
        return flask.redirect('authorize')

    # Build Gmail service
    gmail = build(API_SERVICE_NAME, API_VERSION, credentials=credentials)

    # Fetch message
    message = gmail.users().messages().get(userId="me", id=message_id, format="full", metadataHeaders=None).execute()

    # Initialize a dictionary to store relevant header values
    header_values = {
        "subject": None,
        "date": None,
        "from": None,
        "to": None,
        "cc": None
    }

    headers=message["payload"]["headers"]
    parts = message["payload"]["parts"]
    # print(headers)

    for header in headers:
        name = header["name"].lower()
        if name in header_values:
            header_values[name] = header["value"]

    # Extracting plain text message
    def get_plain_text_body(parts):
        for part in parts:
            if part['mimeType'] == 'text/plain':
                body = part['body']['data']
                decoded_body = base64.urlsafe_b64decode(body).decode('utf-8')
                return decoded_body
        return None

    plain_text_message = get_plain_text_body(parts)

    # Create a message text dictionary
    message_text = {
        "subject": header_values.get('subject'),
        "date": header_values.get('date'),
        "from": header_values.get('from'),
        "to": header_values.get('to'),
        "cc": header_values.get('cc'),
        "message": plain_text_message
    }

    print(message_text)

    # Update session with latest credentials (optional)
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.jsonify(**message)

if __name__ == "__main__":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    app.run("localhost", 8000, debug=True)