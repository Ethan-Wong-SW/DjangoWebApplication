import requests
import random
#print(random.randint(1, 10))
import json

# Replace with your Django app's base URL
base_url = 'http://127.0.0.1:8000/datatb/product/'

# Define the endpoint URL
endpoint_url = 'add/'

url = base_url + endpoint_url

# Generate random values for the input fields
random_name = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=10))
random_info = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=4))
random_price = random.randint(1, 100)

# Define the form data with random values
form_data = {
    'name': random_name,
    'info': random_info,
    'price': random_price,
}

# Define the headers
headers = {
    'Content-Type': 'application/json',  # Specify the JSON content type
    # Replace with valid CSRF and session tokens if needed
    'Cookie': 'csrftoken=VALID_CSRF_TOKEN; sessionid=VALID_SESSION_ID',
}

try:
    print("Request Payload:")
    print(json.dumps(form_data, indent=2))

    # Send the POST request
    response = requests.post(url, headers=headers, data=json.dumps(form_data))

    # Check if the request was successful (status code 200 or 201)
    if response.status_code in [200, 201]:
        print("Request successful!")
        print("Response:")
        print(response.text)
    else:
        print(f"Request failed with status code: {response.status_code}")
        print("Response:")
        print(response.text)
except requests.exceptions.RequestException as e:
    print("Request failed:", e)
