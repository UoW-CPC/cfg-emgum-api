from flask import Flask
from flask import jsonify, abort, Response
from flask_restful import request, reqparse, fields, marshal, Resource
from keycloak import KeycloakOpenID
from keycloak import KeycloakAdmin
import os
import json
import csv
import string
import requests
import jsonurl
from app import app
import random
from random import randint

##### CONSTANT VALUES
# http codes
# Success
HTTP_CODE_OK = 200
HTTP_CODE_CREATED = 201
# Clients's errors
HTTP_CODE_BAD_REQUEST = 400
HTTP_CODE_UNAUTHORIZED = 401
HTTP_CODE_NOT_FOUND = 404
HTTP_CODE_CONFLICT = 409
#HTTP_CODE_LOCKED = 423
# Server error
HTTP_CODE_SERVER_ERR = 500

PASSWD_MIN_LEN = 8 # characters
PASSWD_MAX_LEN = 16 # characters

##### END - CONSTANT VALUES


##### GLOBAL CONFIGURATION AND VARIABLES
# Loading configuration from config.json file
with open('config.json', 'r') as f:
	config = json.load(f)

KEYCLOAK_SERVER = config['DEFAULT']['KEYCLOAK_SERVER']
KEYCLOAK_REALM = config['DEFAULT']['KEYCLOAK_REALM']

MANAGER_USERNAME = config['DEFAULT']['MANAGER_USERNAME']
MANAGER_PASSWORD = config['DEFAULT']['MANAGER_PASSWORD']

# import the resource of all messages
reader = csv.DictReader(open('resource.csv', 'r'))
msg_dict = {}
for row in reader:
    msg_dict[row['Code']] = row['Message']
##### END - GLOBAL CONFIGURATION AND VARIABLES


##### INTERNAL FUNCTIONS
def create_json_response(http_code, message_label, info_for_developer="", additional_json = {}):
	data = {
		'code' : http_code,
		'user message'  : msg_dict[message_label],
		'developer message' : msg_dict[message_label] + info_for_developer
	}
	data.update(additional_json)   
	js = json.dumps(data)
	resp = Response(js, status=http_code, mimetype='application/json')
	return resp


def retrieve_realm_admin_access_token():
	request_token_link = KEYCLOAK_SERVER + "realms/" + KEYCLOAK_REALM + "/protocol/openid-connect/token"
	#print request_token_link

	payload = {"client_id" : "admin-cli",
		"username" : MANAGER_USERNAME,
		"password" : MANAGER_PASSWORD,
		"grant_type" : "password"}

	r = requests.post(request_token_link,data=payload) # data is in x-www-form-urlencoded
	response  = r.json()
	access_token = response['access_token']

	return access_token

def generate_passwd():
	"""[summary]
	The function randomly generates a password.
	[description]
	This function generates randomly a password from ascii letters and digits. The length of password is limitted from PASSWD_MIN_LEN to PASSWD_MAX_LEN
	
	Returns:
		[type: String] -- [description: a generated password]
	"""
	characters = string.ascii_letters + string.digits # + string.punctuation
	passwd =  "".join(random.choice(characters) for x in range(randint(PASSWD_MIN_LEN, PASSWD_MAX_LEN)))
	return passwd
##### END - INTERNAL FUNCTIONS

##### MODELS
# Keys in client_model (id, name) must match with fields of client object returned by Keycloak
client_model_view = {
	'id': fields.String, # client_id
	'name' : fields.String, # client_name
	'redirectUris' : fields.String,
}

client_model_create = {
	'redirect_uris' : fields.String,
	'client_name' : fields.String
}

client_model_update = {
	'name' : fields.String,
	'clientId' : fields.String, # required. clientId is different from id of client. Id of client is fixed while clientId could be changed
	'baseUrl' : fields.String,
	'redirectUris' : fields.List(fields.String)
}

user_model_view = {
	'username' : fields.String,
	'email' : fields.String,
	'firstName' : fields.String,
	'lastName' : fields.String
	#'attributes' : fields.String
}

user_model_update = {
	'firstName' : fields.String,
	'lastName' : fields.String
}
##### END - MODELS
##### RESOURCES
class Client(Resource):
	def get(self,client_id):
		access_token = retrieve_realm_admin_access_token()

		headers = {"Authorization":"Bearer " + access_token} # create headers
		clients_link = KEYCLOAK_SERVER + "admin/realms/" + KEYCLOAK_REALM + "/clients/" + client_id
		r = requests.get(clients_link, headers=headers)
		client = r.json()

		return json.dumps(marshal(client, client_model_view)) # Filter the client information with client_model
	def put(self,client_id):
		json_body = request.json
		access_token = retrieve_realm_admin_access_token()
		headers = {"Authorization":"Bearer " + access_token}
		
		clients_link = KEYCLOAK_SERVER + "admin/realms/" + KEYCLOAK_REALM + "/clients/" + client_id
		
		json_body = request.json
		client_new_info = dict(marshal(json_body, client_model_update)) # filter input information
		#print client_new_info
		try:
			r = requests.put(clients_link, json = client_new_info, headers=headers)
			resp = create_json_response(HTTP_CODE_OK,'update_client_successful')
			return resp
		except Exception as e:
			app.logger.error(e) 
			resp = create_json_response(HTTP_CODE_BAD_REQUEST,'fail_to_update_client')
			return resp
	def delete(self,client_id):
		clients_link = KEYCLOAK_SERVER + "admin/realms/" + KEYCLOAK_REALM + "/clients/" + client_id
		
		access_token = retrieve_realm_admin_access_token()
		headers = {"Authorization":"Bearer " + access_token}
		
		try:
			r = requests.delete(clients_link, headers=headers)
			resp = create_json_response(HTTP_CODE_OK,'delete_client_successful')
			return resp
		except Exception as e:
			app.logger.error(e) 
			resp = create_json_response(HTTP_CODE_BAD_REQUEST,'delete_client_failed')
			return resp

class Clients(Resource):
	def post(self):
		json_body = request.json # json_body should be {'client_name' : name_of_application_registering_to_keycloak}

		#headers = {"Authorization":"Bearer <bearer token granted by keycloak server>"}
		headers = {"Authorization":dict(request.headers)['Authorization']}

		#r = "http://<IP address of keycloak server>:8080/auth/realms/<realm name>/clients-registrations/openid-connect"
		request_link = KEYCLOAK_SERVER + "realms/" + KEYCLOAK_REALM + "/clients-registrations/openid-connect"
		
		# Send a request to keycloak server to dynamically register as keycloak client
		try:
			r = requests.post(request_link, json = json_body, headers=headers)
			response = r.json()

			resp = create_json_response(HTTP_CODE_OK,'register_client_success')
			return resp
		except Exception as e:
			app.logger.error(e) 
			resp = create_json_response(HTTP_CODE_BAD_REQUEST,'register_client_failed')
			return resp

class Token(Resource):
	def put(self,token): # refresh/ renew access token. Token = refresh token
		json_body = request.json
		client_id = json_body ['client_id']
		#print client_id

		client_secret = json_body ['client_secret']
		#print client_secret

		try:
			keycloak_openid  = KeycloakOpenID(server_url=KEYCLOAK_SERVER,client_id=client_id, realm_name=KEYCLOAK_REALM, client_secret_key=client_secret,verify=True)
			new_token = keycloak_openid.refresh_token(token)
			resp = create_json_response(HTTP_CODE_OK,"succeed_to_refresh_token",additional_json=new_token)
			return resp
		except:
			resp = create_json_response(HTTP_CODE_UNAUTHORIZED,"fail_to_refresh_token")
			return resp
	def delete(self,token): #  log out. Token = refesh token
		json_body = request.json
		client_id = json_body['client_id']
		#print client_id
		client_secret = json_body['client_secret']
		#print client_secret	
		try:
			keycloak_openid  = KeycloakOpenID(server_url=KEYCLOAK_SERVER,client_id=client_id, realm_name=KEYCLOAK_REALM, client_secret_key=client_secret,verify=True)
			keycloak_openid.logout(token)
			resp = create_json_response(HTTP_CODE_OK,'succeed_to_log_out')
			return resp
		except Exception as e:
			app.logger.error(e)
			resp = create_json_response(HTTP_CODE_BAD_REQUEST,'fail_to_log_out')
			return resp
	def get(self,token): # introspect/ verify token
		parser = reqparse.RequestParser()
		parser.add_argument('client_id')
		parser.add_argument('client_secret')
		args = parser.parse_args()
		client_id = args['client_id']
		client_secret = args['client_secret']
		#print client_id
		#print client_secret
		try:
			keycloak_openid  = KeycloakOpenID(server_url=KEYCLOAK_SERVER,client_id=client_id, realm_name=KEYCLOAK_REALM, client_secret_key=client_secret,verify=True)
			token_info = keycloak_openid.introspect(token)
			if token_info["active"]: # token is valid
				resp = create_json_response(HTTP_CODE_OK,'valid_token',additional_json=token_info)
			else: # token is not valid
				resp = create_json_response(HTTP_CODE_BAD_REQUEST,'invalid_token')
			return resp
		except Exception as e:
			app.logger.error(e)
			resp = create_json_response(HTTP_CODE_BAD_REQUEST,'invalid_token')
			return resp

class Tokens(Resource):
	def post(self): #  retrieve access and refresh token from user's username and password
		json_body = request.json
		username = json_body ['username']
		password = json_body ['password']

		client_id = json_body ['client_id']

		client_secret = json_body ['client_secret']

		try:
			keycloak_openid  = KeycloakOpenID(server_url=KEYCLOAK_SERVER,client_id=client_id, realm_name=KEYCLOAK_REALM, client_secret_key=client_secret,verify=True)
			tokens = keycloak_openid.token(username,password)
			resp = create_json_response(HTTP_CODE_OK,'succeed_to_get_tokens',additional_json=tokens)
			return resp
		except Exception as e:
			app.logger.error(e) 
			resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'fail_to_get_tokens')
			return resp


class UserInfo(Resource):
	def get(self,token): # get user information. Token = access token
		parser = reqparse.RequestParser()
		parser.add_argument('client_id')
		parser.add_argument('client_secret')
		args = parser.parse_args()
		client_id = args['client_id']
		client_secret = args['client_secret']
		#print client_id
		#print client_secret
		try:
			keycloak_openid  = KeycloakOpenID(server_url=KEYCLOAK_SERVER,client_id=client_id, realm_name=KEYCLOAK_REALM, client_secret_key=client_secret,verify=True)
			userinfo = keycloak_openid.userinfo(token)
			#print userinfo
			resp = create_json_response(HTTP_CODE_OK,'succeed_to_get_user_info',additional_json=userinfo)
			return resp
		except Exception as e:
			app.logger.error(e)
			resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'fail_to_get_user_info')
			return resp

##### END - RESOURCES
class Users(Resource):
	def post(self):
		json_body = request.json

		email = json_body ['email']
		username = json_body ['username']
		password = json_body ['password']
		firstname = json_body ['firstname']
		lastname = json_body ['lastname']
		#organization = json_body ['organization']

		#print email
		#print config['DEFAULT']['MANAGER_USERNAME']
		#print config['DEFAULT']['MANAGER_PASSWORD']

		try: 		
			#keycloak_admin = KeycloakAdmin(server_url=KEYCLOAK_SERVER,username=config['DEFAULT']['MANAGER_USERNAME'],password=config['DEFAULT']['MANAGER_PASSWORD'],realm_name=KEYCLOAK_REALM,verify=True)

			#request_link = KEYCLOAK_SERVER + "/admin/realms/" + KEYCLOAK_REALM + "/users"
			new_user = {"email": email,
				"username": username,
				"enabled": True,
				"firstName": firstname,
				"lastName": lastname,
				"realmRoles": ["user_default", ],
				#"attributes": {"organization": organization},
				"credentials": [{"value": password,"type": "password",}]
			}
			''',
				"credentials": [{"value": password,"type": "password",}],
				"realmRoles": ["user_default", ],
				"attributes": {"organization": organization}}'''

			access_token = retrieve_realm_admin_access_token()
			#print access_token

			create_user_link = KEYCLOAK_SERVER + "admin/realms/" + KEYCLOAK_REALM + "/users"
			#print create_user_link
			
			headers = {'Authorization': 'Bearer ' + access_token}

			#headers = {"Authorization":"Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHRGF2RnlXWXlBd2tWRFBpWFFVZnFsdTZJVjhxMldXZVNRQ2praW1WS1RJIn0.eyJqdGkiOiIyNWRhNTkzMy00OTIzLTQwMTItOTdmNC1iYzVmNGZmMDYxYWEiLCJleHAiOjE1MzY4NDAwODYsIm5iZiI6MCwiaWF0IjoxNTM2ODM5Nzg2LCJpc3MiOiJodHRwOi8vMzEuMTcxLjI0NS43NDo4MDgwL2F1dGgvcmVhbG1zL3JlYWxtMDEiLCJhdWQiOiJhZG1pbi1jbGkiLCJzdWIiOiI4MjlhOWE1YS0xMzUxLTQ4ZWYtOTlkNi1hZmRlNjI3YjVmZTciLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhZG1pbi1jbGkiLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiIyODU5OWM4Yi1jYTllLTQyZjctYmQ3ZS1lNzE5NzUxZmZiMDgiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbXSwicmVzb3VyY2VfYWNjZXNzIjp7fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbjAxIn0.Mv8EoGLbDCvtqL8MJ5op1tJUKVWZeyOI2v-4_F8CuHjcp3V8hRz_kKAqaGoKiKHWm0Usf8iHtdECeAnQLYjusiNJh0IinmSjEXj0Cmi9kjHw62xfZk_I8MQtgfOaQVCSy9-cxuTSmbJoVv531TDzOojY_2KI4ul_hZ78Dtk6eKTz1RiiCpIbxnSat1NPWWCJs-wi5Xd9r8a5NmPOfSKlFKFnTT9zWVuxeGLehky-7R7wo7tovIDekJhRtmuNOyLxKzdLKxjpz7VjB_TVhjuJ7xQBKQA4ypEqL9C2K7PCPydpy-kSFEX6_dL8cDt79zFvHEytOt1Rw828PA6ZylKo-w"}
			print headers
			r = requests.post(create_user_link,json=new_user,headers=headers)
			print r.status_code
			if r.status_code == HTTP_CODE_CREATED:
				resp = create_json_response(HTTP_CODE_CREATED,'create_user_successful')
			elif r.status_code == HTTP_CODE_UNAUTHORIZED:
				resp = create_json_response(HTTP_CODE_CREATED,'create_user_failed',info_for_developer="Please check username and password of manager user in config.json file")
			elif r.status_code == HTTP_CODE_CONFLICT:
				resp = create_json_response(HTTP_CODE_BAD_REQUEST,'create_user_failed', info_for_developer = "Email existed")
			else:
				resp = create_json_response(HTTP_CODE_BAD_REQUEST,'create_user_failed')
			return resp
		except Exception as e:
			app.logger.error(e)
			resp = create_json_response(HTTP_CODE_BAD_REQUEST,'create_user_failed')
			return resp
	
class User(Resource):
	def get(self,username): # retrieve user
		users_link = KEYCLOAK_SERVER + "admin/realms/" + KEYCLOAK_REALM + "/users"

		try:
			#keycloak_admin = KeycloakAdmin(server_url=KEYCLOAK_SERVER,username=config['DEFAULT']['MANAGER_USERNAME'],password=config['DEFAULT']['MANAGER_PASSWORD'],realm_name=KEYCLOAK_REALM,verify=True)
			access_token = retrieve_realm_admin_access_token()
			headers = {'Authorization': 'Bearer ' + access_token}

			#headers = {"Authorization":"Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHRGF2RnlXWXlBd2tWRFBpWFFVZnFsdTZJVjhxMldXZVNRQ2praW1WS1RJIn0.eyJqdGkiOiIyNWRhNTkzMy00OTIzLTQwMTItOTdmNC1iYzVmNGZmMDYxYWEiLCJleHAiOjE1MzY4NDAwODYsIm5iZiI6MCwiaWF0IjoxNTM2ODM5Nzg2LCJpc3MiOiJodHRwOi8vMzEuMTcxLjI0NS43NDo4MDgwL2F1dGgvcmVhbG1zL3JlYWxtMDEiLCJhdWQiOiJhZG1pbi1jbGkiLCJzdWIiOiI4MjlhOWE1YS0xMzUxLTQ4ZWYtOTlkNi1hZmRlNjI3YjVmZTciLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhZG1pbi1jbGkiLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiIyODU5OWM4Yi1jYTllLTQyZjctYmQ3ZS1lNzE5NzUxZmZiMDgiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbXSwicmVzb3VyY2VfYWNjZXNzIjp7fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbjAxIn0.Mv8EoGLbDCvtqL8MJ5op1tJUKVWZeyOI2v-4_F8CuHjcp3V8hRz_kKAqaGoKiKHWm0Usf8iHtdECeAnQLYjusiNJh0IinmSjEXj0Cmi9kjHw62xfZk_I8MQtgfOaQVCSy9-cxuTSmbJoVv531TDzOojY_2KI4ul_hZ78Dtk6eKTz1RiiCpIbxnSat1NPWWCJs-wi5Xd9r8a5NmPOfSKlFKFnTT9zWVuxeGLehky-7R7wo7tovIDekJhRtmuNOyLxKzdLKxjpz7VjB_TVhjuJ7xQBKQA4ypEqL9C2K7PCPydpy-kSFEX6_dL8cDt79zFvHEytOt1Rw828PA6ZylKo-w"}
			search_criteria = {
				"username" : username
			}

			r = requests.get(users_link,params=search_criteria,headers=headers)
			'''user_id_keycloak = keycloak_admin.get_user_id(username)
			print user_id_keycloak

			user = keycloak_admin.get_user(user_id_keycloak)
			print user'''

			#response = dict(marshal(r.json(), user_model_view)[0])
			response = r.json()[0]
			print response
			resp = create_json_response(HTTP_CODE_OK,"retrieve_user_successful",additional_json=response)
			
			return resp
		except Exception as e:
			app.logger.error(e)
			resp = create_json_response(HTTP_CODE_BAD_REQUEST,"retrieve_user_failed")

	def put(self,username): # update user
		#username = request.values.get("username")
		users_link = KEYCLOAK_SERVER + "admin/realms/" + KEYCLOAK_REALM + "/users/" 
		json_body = request.json
		try:
			access_token = retrieve_realm_admin_access_token()
			headers = {'Authorization': 'Bearer ' + access_token}

			update_info = dict(marshal(request.json, user_model_update))
			#print update_info

			search_criteria = {
				"username" : username
			}

			r = requests.get(users_link,params=search_criteria,headers=headers)
			user_id  = r.json()[0]['id']
			update_users_link = users_link + user_id
			#print update_users_link

			r = requests.put(update_users_link,json=update_info,headers=headers)
			#print r.text
			resp = create_json_response(HTTP_CODE_OK,"update_user_successful")
			
			return resp
		except Exception as e:
			app.logger.error(e)
			resp = create_json_response(HTTP_CODE_BAD_REQUEST,"update_user_failed")
			return resp
	def delete(self,username): # delete user
		users_link = KEYCLOAK_SERVER + "admin/realms/" + KEYCLOAK_REALM + "/users/" 
		try:
			access_token = retrieve_realm_admin_access_token()
			headers = {'Authorization': 'Bearer ' + access_token}
			#print headers

			search_criteria = {
				"username" : username
			}
			r = requests.get(users_link,params=search_criteria,headers=headers)
			user_id  = r.json()[0]['id']
			#print user_id

			delete_users_link = users_link + user_id
			#print delete_users_link

			r = requests.delete(delete_users_link,headers=headers)
			#print r.text

			resp = create_json_response(HTTP_CODE_OK,"delete_user_successful")
			return resp  
		except Exception as e:
			app.logger.error(e)
			resp = create_json_response(HTTP_CODE_BAD_REQUEST,"delete_user_failed")
			return resp

class UserPassword(Resource):
	#def post(self, username): # create a new password (after user has reset password)
	#def put(self, username): # change password
	def delete(self, username): # reset password
		users_link = KEYCLOAK_SERVER + "admin/realms/" + KEYCLOAK_REALM + "/users/" 
		try:
			access_token = retrieve_realm_admin_access_token()
			headers = {'Authorization': 'Bearer ' + access_token}
			#print headers

			search_criteria = {
				"username" : username
			}
			r = requests.get(users_link,params=search_criteria,headers=headers)
			user_id  = r.json()[0]['id']
			#print user_id

			reset_password_link = users_link + user_id + "/reset-password"
			#print reset_password_link

			temp_password = generate_passwd()
			#print temp_password
			new_credentials = {
				"value": temp_password,
				"type": "password"
			}
			r = requests.put(reset_password_link,json=new_credentials,headers=headers)
			#print r.status_code
			#print r.text

			resp = create_json_response(HTTP_CODE_OK,"reset_user_password_successful")
			return resp  
		except Exception as e:
			app.logger.error(e)
			resp = create_json_response(HTTP_CODE_BAD_REQUEST,"reset_user_password_failed")
			return resp