# Update on 16:00, 10.10.2018
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
#import jsonurl
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

DEBUG_MODE = False
##### END - CONSTANT VALUES


##### GLOBAL CONFIGURATION AND VARIABLES
# Loading configuration from config.json file
cfg_path = os.path.abspath(os.path.join(os.path.dirname(__file__),".."))
json_path = os.path.join(cfg_path, 'config.json')
with open(json_path,'r') as f:
	config = json.load(f)

KEYCLOAK_SERVER = config['DEFAULT']['KEYCLOAK_SERVER']
KEYCLOAK_REALM = config['DEFAULT']['KEYCLOAK_REALM']

SUPERUSER_NAME = config['DEFAULT']['SUPERUSER_NAME']
SUPERUSER_PASSWORD = config['DEFAULT']['SUPERUSER_PASSWORD']

# import the resource of all messages
csv_path = os.path.join(cfg_path, 'resource.csv')
reader = csv.DictReader(open(csv_path, 'r'))
msg_dict = {}
for row in reader:
    msg_dict[row['Code']] = row['Message']
##### END - GLOBAL CONFIGURATION AND VARIABLES


##### INTERNAL FUNCTIONS
def create_json_response(http_code, message_label, info_for_developer="", additional_json = {}):
	data = {
		'code' : http_code,
		'message'  : msg_dict[message_label] + info_for_developer
	}
	data.update(additional_json)   
	js = json.dumps(data)
	resp = Response(js, status=http_code, mimetype='application/json')
	return resp


def retrieve_realm_admin_access_token():
	request_token_link = KEYCLOAK_SERVER + "realms/" + KEYCLOAK_REALM + "/protocol/openid-connect/token"

	payload = {"client_id" : "admin-cli",
		"username" : SUPERUSER_NAME,
		"password" : SUPERUSER_PASSWORD,
		"grant_type" : "password"}

	try:	
		r = requests.post(request_token_link,data=payload) # data is in x-www-form-urlencoded
		response  = r.json()

		access_token = response['access_token']

		return access_token
	except Exception as e:
		app.logger.error(e)
		raise e

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
	'client_id': fields.String, # id of client
	'client_name' : fields.String, # client_name
	'client_secret' : fields.String,
	'client_secret_expires_at': fields.Integer, # fields.DateTime(dt_format='rfc822')
	'redirect_uris' : fields.List(fields.String),
	'registration_access_token': fields.String,
	#'subject_type': fields.String,
	#'response_types': fields.String,
	#'token_endpoint_auth_method' : fields.String,
	#'registration_client_uri' : fields.String,
	#'tls_client_certificate_bound_access_tokens' : fields.String,
	#'grant_types': fields.List(fields.String) # List
}

token_model_view = {
	'session_state' : fields.String,
	'access_token' : fields.String,
	#'not-before-policy' : fields.Integer,
	'expires_in' : fields.Integer,
	#'token_type' : fields.String,
	'refresh_expires_in': fields.Integer,
	'refresh_token': fields.String
}

token_verification_view = {
	'sub': fields.String, # id of user
	'resource_access': fields.Nested({
		'account':fields.Nested({
			'roles': fields.List(fields.String)
		})
	}),
	#'nbf': fields.Integer, 
	'session_state': fields.String,
	'aud': fields.String, 
	#'jti': fields.String,
	'given_name': fields.String,
	#'scope': fields.String,
	'email': fields.String,
	'username': fields.String,
	#'preferred_username': fields.String,
	'client_id': fields.String,
	#'iat': fields.Integer,
	'active': fields.Boolean, 
	#'typ': fields.String, 
	'name': fields.String,
	'family_name': fields.String,
	#'allowed-origins': fields.String, 
	#'realm_access': fields.Nested({
	#	'roles': fields.List(fields.String)
	#}
	#),
	'iss': fields.String, 
	#'email_verified': fields.Boolean, 
	#'acr': fields.Integer, 
	'exp': fields.Integer,
	#'auth_time': fields.Integer, 
	'azp': fields.String
}

user_model_view = {
	'username' : fields.String,
	'email' : fields.String,
	'firstName' : fields.String,
	'lastName' : fields.String,
	'id': fields.String,
	'enabled': fields.Boolean,
	'totp': fields.Boolean,
	'emailVerified':fields.Boolean,
	'disableableCredentialTypes':fields.List(fields.String),
	'requiredActions': fields.List(fields.String),
	'notBefore': fields.Integer,
	'access': fields.Nested({
		'manageGroupMembership':fields.Boolean,
		'view': fields.Boolean,
		'mapRoles': fields.Boolean,
		'impersonate': fields.Boolean,
		'manage': fields.Boolean
	})
	#'attributes' : fields.String
}

user_model_update = {
	'firstName': fields.String(attribute='firstname'),
	'lastName': fields.String(attribute='lastname')
}

## END - MODELS

##### RESOURCES
### CLIENT
class Client(Resource): 
	def get(self,client_id):
		auth = request.headers.get('authorization')
		#app.logger.error(auth)
		#auth = request.headers
		headers = {"Authorization":auth}
		#token = dict(request.headers)['Authorization']
		#headers = {"Authorization":token} # create headers
		clients_link = KEYCLOAK_SERVER + "realms/" + KEYCLOAK_REALM + "/clients-registrations/openid-connect/" + client_id

		if DEBUG_MODE:
			print("RETRIEVE A CLIENT")
			print("headers: ", headers)
			print("clients_link: ", clients_link)
			print("client_id: ", client_id)

		received_response = False
		try:
			r = requests.get(clients_link, headers=headers)
			client = r.json()

			received_response = True 

			client_filtered = dict(marshal(client, client_model_view))
			if DEBUG_MODE:
				print("client: ", client)
				print("filtered client: ", client_filtered)

			client_id = client['client_id']	# if r returns error, client['client_id'] does not exist
			resp = create_json_response(HTTP_CODE_OK,'retrieve_client_successful', additional_json=client)
			return resp	
		except Exception as e:
			app.logger.error(e)
			if(received_response):
				resp = create_json_response(HTTP_CODE_BAD_REQUEST,'retrieve_client_failed', additional_json = client)
			else:
				resp = create_json_response(HTTP_CODE_BAD_REQUEST,'retrieve_client_failed')
			return resp
		

	def put(self,client_id):
		json_body = request.json
		
		auth = request.headers.get('authorization')
		headers = {"Authorization":auth}
		#headers = {"Authorization":dict(request.headers)['Authorization']} # create headers
		
		clients_link = KEYCLOAK_SERVER + "realms/" + KEYCLOAK_REALM + "/clients-registrations/openid-connect/" + client_id
		
		json_body.update({'client_id' : client_id}) # Keycloak REST API requires client_id in json_body; therefore, we add this information here		
		
		if DEBUG_MODE:
			print("UPDATE CLIENT")
			print("json_body: ", json_body)
			print("headers: ", headers)
			print("clients_link: ", clients_link)

		
		try:
			r = requests.put(clients_link, json = json_body, headers=headers)

			filtered_response = dict(marshal(json.loads(r.text), client_model_view)) # filter the response to match with client_model_view
			filtered_none_response = dict(filter(lambda item: item[1] is not None, filtered_response.items())) # remove all fields with value None

			if DEBUG_MODE:
				print("response: ", r.status_code)
				print("updated client info: ", r.text)
				print("filtered updated client info: ", filtered_none_response)

			if r.status_code == HTTP_CODE_OK:
				resp = create_json_response(HTTP_CODE_OK,'update_client_successful',additional_json=filtered_none_response)
			else:
				resp = create_json_response(HTTP_CODE_BAD_REQUEST,'fail_to_update_client')

			return resp
		except Exception as e:
			app.logger.error(e) 
			resp = create_json_response(HTTP_CODE_BAD_REQUEST,'fail_to_update_client')
			return resp

	def delete(self,client_id):
		auth = request.headers.get('authorization')
		headers = {"Authorization":auth}
		#headers = {"Authorization":dict(request.headers)['Authorization']} # create headers

		clients_link = KEYCLOAK_SERVER + "realms/" + KEYCLOAK_REALM + "/clients-registrations/openid-connect/" + client_id

		if DEBUG_MODE:
			print("DELETE CLIENT")
			print("headers: ", headers)
			print("client_id: ", client_id)
			print("clients_link: ", clients_link)

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
		'''[summary]
		Dynamically register a client
		[description]
		For further details on which information could be updated by Keycloak client itself, please refer to attributes of ClientRepresentation at https://github.com/keycloak/keycloak/blob/master/core/src/main/java/org/keycloak/representations/oidc/OIDCClientRepresentation.java
		Returns:
			[type] -- [description]
		'''
		json_body = request.json # json_body should be {'client_name' : name_of_application_registering_to_keycloak, 'redirect_uris' : list of redirect uris}

		#headers = {"Authorization":"Bearer <bearer token granted by keycloak server>"}


		auth = request.headers.get('authorization')
		#headers = {"Authorization":dict(request.headers)['Authorization']}
		headers = {"Authorization":auth}
		#r = "http://<IP address of keycloak server>:8080/auth/realms/<realm name>/clients-registrations/openid-connect"
		request_link = KEYCLOAK_SERVER + "realms/" + KEYCLOAK_REALM + "/clients-registrations/openid-connect"
		
		if DEBUG_MODE :
			print("CREATE CLIENT")
			print("request link: ",request_link)
			print("headers: ",headers)
			print("json_body: ",json_body)

		# Send a request to keycloak server to dynamically register as keycloak client
		try:
			r = requests.post(request_link, json = json_body, headers=headers)
			response = r.json()

			if DEBUG_MODE :
				print("response: ",response)
				print("status code: ",r.status_code)

			if(r.status_code==HTTP_CODE_CREATED):
				resp = create_json_response(HTTP_CODE_OK,'register_client_success',additional_json=response)
			else:
				resp = create_json_response(HTTP_CODE_BAD_REQUEST,'register_client_failed',additional_json=response)
			return resp
		except Exception as e:
			app.logger.error(e) 
			resp = create_json_response(HTTP_CODE_BAD_REQUEST,'register_client_failed')
			return resp
### END - CLIENT

### TOKEN
class Token(Resource):
	def put(self,token): # refresh/ renew access token. Token = refresh token
		json_body = request.json
		client_id = json_body ['client_id']

		client_secret = json_body ['client_secret']

		if DEBUG_MODE:
			print("RENEW TOKENS")
			print("json body: ", json_body)

		#app.logger.info("RENEW TOKENS")
		#app.logger.info("client_id: " + client_id)

		try:
			keycloak_openid  = KeycloakOpenID(server_url=KEYCLOAK_SERVER,client_id=client_id, realm_name=KEYCLOAK_REALM, client_secret_key=client_secret,verify=True)
			new_token = keycloak_openid.refresh_token(token)
			if DEBUG_MODE:
				print('new token: ', new_token)			
			resp = create_json_response(HTTP_CODE_OK,"succeed_to_refresh_token",additional_json=new_token)
			return resp
		except:
			resp = create_json_response(HTTP_CODE_UNAUTHORIZED,"fail_to_refresh_token")
			return resp
	def delete(self,token): #  log out. Token = refesh token
		json_body = request.json
		client_id = json_body['client_id']

		client_secret = json_body['client_secret']

		try:
			keycloak_openid  = KeycloakOpenID(server_url=KEYCLOAK_SERVER,client_id=client_id, realm_name=KEYCLOAK_REALM, client_secret_key=client_secret,verify=True)
			keycloak_openid.logout(token)
			resp = create_json_response(HTTP_CODE_OK,'succeed_to_log_out')
			if DEBUG_MODE:
				print("DELETE TOKENS")
			#app.logger.info("DELETE TOKENS")
			#app.logger.info("client_id: " + client_id)	

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

		try:
			keycloak_openid  = KeycloakOpenID(server_url=KEYCLOAK_SERVER,client_id=client_id, realm_name=KEYCLOAK_REALM, client_secret_key=client_secret,verify=True)
			token_info = keycloak_openid.introspect(token)
			filtered_token_info = dict(marshal(token_info,token_verification_view))

			if DEBUG_MODE:
				print("VERIFY TOKEN")
				print("token info: ", token_info)
				print("filtered token info: ", filtered_token_info)
			#app.logger.info("VERIFY TOKEN")
			#app.logger.info("client_id: " + client_id)
			#app.logger.info("token info: " + token_info)

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
	def post(self): #  retrieve access and refresh token from user's username and password. Only clent allowed for direct access grants could request
		json_body = request.json
		username = json_body ['username']
		password = json_body ['password']

		client_id = json_body ['client_id']

		client_secret = json_body ['client_secret']

		if DEBUG_MODE:
			print('RETRIEVE TOKENS')
			print("json body: ", json_body)
		#app.logger.info('RETRIEVE TOKENS')
		#app.logger.info("client_id: " + client_id)

		try:
			keycloak_openid  = KeycloakOpenID(server_url=KEYCLOAK_SERVER,client_id=client_id, realm_name=KEYCLOAK_REALM, client_secret_key=client_secret,verify=True)
			tokens = keycloak_openid.token(username,password)

			filtered_tokens = dict(marshal(tokens, token_model_view))

			if DEBUG_MODE:
				print("Tokens: ", tokens)
				print("Filtered tokens: ", filtered_tokens)
			#app.logger.info("Tokens: " + tokens)

			resp = create_json_response(HTTP_CODE_OK,'succeed_to_get_tokens',additional_json=filtered_tokens)
			return resp
		except Exception as e:
			app.logger.error(e) 
			resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'fail_to_get_tokens')
			return resp
### END - TOKEN

### USERINFO
class UserInfo(Resource):
	def get(self,token): # get user information. Token = access token
		parser = reqparse.RequestParser()
		parser.add_argument('client_id')
		parser.add_argument('client_secret')
		args = parser.parse_args()
		client_id = args['client_id']
		client_secret = args['client_secret']

		try:
			keycloak_openid  = KeycloakOpenID(server_url=KEYCLOAK_SERVER,client_id=client_id, realm_name=KEYCLOAK_REALM, client_secret_key=client_secret,verify=True)
			userinfo = keycloak_openid.userinfo(token)
			
			if DEBUG_MODE:
				print('\nRETRIEVE USER INFORMATION: ')

			resp = create_json_response(HTTP_CODE_OK,'succeed_to_get_user_info',additional_json=userinfo)
			return resp
		except Exception as e:
			app.logger.error(e)
			resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'fail_to_get_user_info')
			return resp

class Users(Resource):
	def post(self):
		json_body = request.json
		
		email = json_body ['email']
		username = json_body ['username']
		password = json_body ['password']
		firstname = json_body ['firstname']
		lastname = json_body ['lastname']
		#organization = json_body ['organization']

		if DEBUG_MODE:
			print('\nCREATE USER')
			print('user name: ', username)
			print('email: ', email)
		try: 		
			new_user = {"email": email,
				"username": username,
				"enabled": True,
				"firstName": firstname,
				"lastName": lastname,
				"realmRoles": ["user_default", ],
				#"attributes": {"organization": organization},
				"credentials": [{"value": password,"type": "password",}]
			}

			access_token = retrieve_realm_admin_access_token()

			if DEBUG_MODE:
				print('super user access token: ', access_token)

			create_user_link = KEYCLOAK_SERVER + "admin/realms/" + KEYCLOAK_REALM + "/users"
			
			headers = {'Authorization': 'Bearer ' + access_token}

			r = requests.post(create_user_link,json=new_user,headers=headers)

			if DEBUG_MODE:
				print('response: ', r.status_code, '-', r.text)

			if r.status_code == HTTP_CODE_CREATED:
				resp = create_json_response(HTTP_CODE_CREATED,'create_user_successful')
			elif r.status_code == HTTP_CODE_UNAUTHORIZED:
				resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'create_user_failed',info_for_developer="Please ensure that super user has right to manage other users")
			elif r.status_code == HTTP_CODE_CONFLICT:
				resp = create_json_response(HTTP_CODE_BAD_REQUEST,'create_user_failed', info_for_developer = "Email existed")
			else:
				resp = create_json_response(HTTP_CODE_BAD_REQUEST,'create_user_failed',info_for_developer="Please check username and password of super user in config.json file")
			return resp
		except Exception as e:
			app.logger.error(e)
			resp = create_json_response(HTTP_CODE_BAD_REQUEST,'create_user_failed')
			return resp
### END - USERINFO

### USER
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

			if DEBUG_MODE:
				print('RETRIEVE A USER')
				print('User:', r.text)

			response = r.json()[0]
			filtered_response = dict(marshal(response, user_model_view))

			if DEBUG_MODE:
				print('Filtered user info:', filtered_response)
			#print response
			resp = create_json_response(HTTP_CODE_OK,"retrieve_user_successful",additional_json=response)
			
			return resp
		except Exception as e:
			app.logger.error(e)
			resp = create_json_response(HTTP_CODE_BAD_REQUEST,"retrieve_user_failed")
			return resp

	def put(self,username): # update user
		users_link = KEYCLOAK_SERVER + "admin/realms/" + KEYCLOAK_REALM + "/users/" 
		json_body = request.json

		new_user_info = dict(marshal(json_body,user_model_update))
		
		if DEBUG_MODE:
			print('\nUPDATE USER')
			print('Json body:', json_body)
			print('New user info: ', new_user_info)


		try:
			access_token = retrieve_realm_admin_access_token()
			headers = {'Authorization': 'Bearer ' + access_token}

			search_criteria = {
				"username" : username
			}

			r = requests.get(users_link,params=search_criteria,headers=headers)
			user_id  = r.json()[0]['id']
			update_users_link = users_link + user_id

			r = requests.put(update_users_link,json=new_user_info,headers=headers)

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

			search_criteria = {
				"username" : username
			}
			r = requests.get(users_link,params=search_criteria,headers=headers)
			user_id  = r.json()[0]['id']

			delete_users_link = users_link + user_id

			r = requests.delete(delete_users_link,headers=headers)

			resp = create_json_response(HTTP_CODE_OK,"delete_user_successful")
			return resp  
		except Exception as e:
			app.logger.error(e)
			resp = create_json_response(HTTP_CODE_BAD_REQUEST,"delete_user_failed")
			return resp
### END - USER

### ENDPOINT
class Endpoint(Resource):
	def get(self): # return endpoint of public key
		endpoint = KEYCLOAK_SERVER + "realms/" + KEYCLOAK_REALM + "/protocol/openid-connect/certs"
		epJson = {'pk_endpoint':endpoint}
		resp = create_json_response(HTTP_CODE_OK,'endpoint_successful',additional_json=epJson)
		return resp
### END - ENDPOINT

### RPT (Relying party token)
class Rpt(Resource):
	def post(self): # retrieve rpt token
		json_body = request.json
		rs_id = json_body ['resource_server_id']
		resource = json_body ['resource_name']
		payload = {"audience":rs_id, "permission": resource, "grant_type":"urn:ietf:params:oauth:grant-type:uma-ticket"} 
		
		access_token = request.headers.get('authorization')
		headers = {"Authorization":access_token}

		token_link = KEYCLOAK_SERVER + "realms/" + KEYCLOAK_REALM + "/protocol/openid-connect/token"
		if DEBUG_MODE:
			print('RETRIEVE TOKENS')
			print("json body: ", json_body)
		#app.logger.info('RETRIEVE TOKENS')
		#app.logger.info("client_id: " + client_id)

		try:
			#keycloak_openid  = KeycloakOpenID(server_url=KEYCLOAK_SERVER,client_id=rs_id, realm_name=KEYCLOAK_REALM, client_secret_key=rs_secret,verify=True)
			#rpt = keycloak_openid.entitlement(access_token, rs_id)
			r = requests.post(token_link,headers=headers,data=payload) # data is in x-www-form-urlencoded
			response  = r.json()

			if DEBUG_MODE:
				print ("Response:",response)

			rpt = response['access_token']

			if DEBUG_MODE:
				print("Tokens: ", rpt)
			#app.logger.info("Tokens: " + tokens)


			resp = create_json_response(HTTP_CODE_OK,'succeed_to_get_tokens',additional_json={"rpt token":rpt})
			return resp
		except Exception as e:
			app.logger.error(e) 
			resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'fail_to_get_rpt', additional_json=response)
			return resp
### END - RPT
##### END - RESOURCES