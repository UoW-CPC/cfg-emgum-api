import os.path
import subprocess
import sys
import requests
import os
import json

http_code_ok = 200
#http_code_created = 201
#http_code_bad_request = 404
#API_URL = "http://127.0.0.1:5000/v1.0"
API_URL = "http://178.22.68.132/v1.0"

class cfg_test_lib(object):

    def __init__(self):
        #self._sut_path = os.path.join(os.path.dirname(__file__),
         #                             '..', 'sut', 'login.py')
        self._status = ''
        self._data = ''

    '''def print_hello(self):
        url     = 'http://127.0.0.1:5003/v1.0/'
        res = requests.get(url)
        self._status = res.status_code'''

    def status_should_be(self, expected_status):
        if expected_status != str(self._status):
            raise AssertionError("Expected status to be '%s' but was '%s'."
                                 % (expected_status, self._status))

    def data_should_be(self, expected_data):
        if expected_data != str(self._data):
            raise AssertionError("Expected data to be '%s' but was '%s'."
                               % (expected_data, self._data))

    def dynamic_register_a_client(self, initial_reg_token, client_name, uris):
        url     = API_URL + '/clients'
        payload = {'client_name': client_name, 'redirect_uris': uris}
        headers = {"Authorization": 'Bearer ' + initial_reg_token}
        res = requests.post(url, json=payload, headers = headers)
        json_data = json.loads(res.text)
        self._status = json_data['code']
        return json_data['client_id'],json_data['client_secret'], json_data['registration_access_token']#['client_id'], json_data['client_secret']} #json_data['registration_access_token'], 

    def delete_a_client(self, client_id, reg_token):
        url     = API_URL + '/clients/' + client_id
        headers = {"Authorization": 'Bearer ' + reg_token}
        res = requests.delete(url, headers = headers)
        json_data = json.loads(res.text)
        self._status = json_data['code']


    def retrieve_a_client(self, client_id, reg_token):
        url     = API_URL + '/clients/' + client_id
        headers = {"Authorization": 'Bearer ' + reg_token}
        res = requests.get(url, headers = headers)
        json_data = json.loads(res.text)
        self._status = json_data['code']


    def update_a_client(self, client_id, reg_token, new_redirect_uris, new_client_name):
        url     = API_URL + '/clients/' + client_id
        headers = {"Authorization": 'Bearer ' + reg_token}
        payload = {'redirect_uris': new_redirect_uris, 'client_name' : new_client_name}
        res = requests.put(url, json=payload, headers = headers)
        json_data = json.loads(res.text)
        self._status = json_data['code']
        self._data = json_data['client_name']
        return json_data['registration_access_token']
    
    def retrieve_all_tokens(self, client_id, client_secret, user_name, password):
        url     = API_URL + '/tokens'
        payload = {'username': user_name, 'password': password, "client_id": client_id, "client_secret": client_secret}
        res = requests.post(url, json=payload)
        json_data = json.loads(res.text)
        self._status = json_data['code']
        return json_data['access_token'], json_data['refresh_token']

    def renew_access_token(self, refresh_token, client_id, client_secret):
        url     = API_URL + '/tokens/' + refresh_token
        payload = {"client_id": client_id, "client_secret": client_secret}
        res = requests.put(url, json=payload)
        json_data = json.loads(res.text)
        self._status = json_data['code']
        return json_data['access_token'], json_data['refresh_token']

    def introspect_access_token(self, access_token, client_id, client_secret):
        url     = API_URL + '/tokens/' + access_token
        payload = {"client_id": client_id, "client_secret": client_secret}
        res = requests.get(url, params=payload)
        json_data = json.loads(res.text)
        self._status = json_data['code']

    def delete_tokens(self, refresh_token, client_id, client_secret):
        url     = API_URL + '/tokens/' + refresh_token
        payload = {"client_id": client_id, "client_secret": client_secret}
        res = requests.delete(url, json=payload)
        json_data = json.loads(res.text)
        self._status = json_data['code']

    def retrieve_user_info(self, access_token, client_id, client_secret):
        url     = API_URL + '/userinfo/' + access_token
        payload = {"client_id": client_id, "client_secret": client_secret}
        res = requests.get(url, params=payload)
        json_data = json.loads(res.text)
        self._status = json_data['code']
        
    def add_a_user(self, username, password, firstname, lastname, email):
        url     = API_URL + '/users'
        payload = {"username": username, "password": password, "firstname": firstname, "lastname": lastname, "email": email}
        res = requests.post(url, json=payload)
        json_data = json.loads(res.text)
        self._status = json_data['code']

    def retrieve_a_user(self, username):
        url     = API_URL + '/users/' + username
        res = requests.get(url)
        json_data = json.loads(res.text)
        self._status = json_data['code']
        if self._status==http_code_ok:
            self._data = json_data['firstName']

    def delete_a_user(self, username):
        url     = API_URL + '/users/' + username
        res = requests.delete(url)
        json_data = json.loads(res.text)
        self._status = json_data['code']

    def update_a_user(self, username, firstname, lastname):
        url     = API_URL + '/users/' + username
        payload = {"firstname": firstname, "lastname": lastname}
        res = requests.put(url,json=payload)
        json_data = json.loads(res.text)
        self._status = json_data['code']
