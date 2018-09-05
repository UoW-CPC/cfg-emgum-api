from flask import Flask
from flask import jsonify, abort, Response
from flask_restful import request
from keycloak import KeycloakOpenID
from keycloak import KeycloakAdmin
import os
import json
import csv
import string
import requests
import jsonurl

# http codes
# Success
HTTP_CODE_OK = 200
# HTTP_CODE_CREATED = 201
# Clients's errors
HTTP_CODE_BAD_REQUEST = 400
HTTP_CODE_UNAUTHORIZED = 401
HTTP_CODE_NOT_FOUND = 404
#HTTP_CODE_LOCKED = 423
# Server error
HTTP_CODE_SERVER_ERR = 500

# import the resource of all messages
'''reader = csv.DictReader(open('resource.csv', 'r'))
msg_dict = {}
for row in reader:
	msg_dict[row['Code']] = row['Message']'''


#SERVER_URL = "http://10.20.151.49:8180/auth/"
#CLIENT_ID = "appDM"
#REALM_NAME = "demo"
#CLIENT_SECRET = "d5e62000-4f60-40c3-8642-abfd0a9523e2"

#SERVER_URL = "http://31.171.247.142:8080/auth/"
#CLIENT_ID = "app02"
#REALM_NAME = "app01"
#CLIENT_SECRET = "581ff333-aba1-4f45-9f27-0a06704d099b" #app2
#CLIENT_SECRET = "e532ea62-2743-4cea-89b3-ffc58664f739" #APP1

#keycloak_openid = KeycloakOpenID(server_url=SERVER_URL,client_id=CLIENT_ID, realm_name=REALM_NAME, client_secret_key=CLIENT_SECRET,verify=True)
#token = keycloak_openid.token("user01","123")  


#def get_accesstoken_api():
#	return token['access_token']

#def get_refreshtoken():
#	return token['refresh_token']

PASSWD_MIN_LEN = 8 # characters
PASSWD_MAX_LEN = 16 # characters

registration_endpoint = "http://31.171.246.187:8080/auth/realms/realm01/clients-registrations/openid-connect"

def set_client_api():
	serverurl = request.values.get("server")
	realmname = request.values.get("realm")
	clientid = request.values.get("id")
 	clientsecret = request.values.get("secret")
	global keycloak_openid 
	keycloak_openid  = KeycloakOpenID(server_url=serverurl,client_id=clientid, realm_name=realmname, client_secret_key=clientsecret,verify=True)

	# not yet: check if client is valid or not
	data = {
			'code' : HTTP_CODE_OK,
			'user message'  : 'set client successfully',
			'developer message' : 'set client successfully'
	}   
	js = json.dumps(data)
	resp = Response(js, status=HTTP_CODE_OK, mimetype='application/json')
	return resp

def get_tokens_api():
	username = request.values.get("username")
	password = request.values.get("password")
	try:
		token = keycloak_openid.token(username,password)
	except Exception as e:
		raise e
		data = {
			'code' : HTTP_CODE_UNAUTHORIZED,
			'user message'  : 'Invalid user credentials',
			'developer message' : 'Invalid user credentials'
		}   
		js = json.dumps(data)
		resp = Response(js, status=HTTP_CODE_UNAUTHORIZED, mimetype='application/json')
		return resp
		
	js = json.dumps(token)
	resp = Response(js, status=HTTP_CODE_OK, mimetype='application/json')
	return resp
    
def get_userinfo_api():
	access_token = request.values.get("token")
	try:
		userinfo = keycloak_openid.userinfo(access_token)
	except:
		data = {
			'code' : HTTP_CODE_UNAUTHORIZED,
			'user message'  : 'Authentication error: Invalid token',
			'developer message' : 'Authentication error: Invalid token'
		}   
		js = json.dumps(data)
		resp = Response(js, status=HTTP_CODE_UNAUTHORIZED, mimetype='application/json')
		return resp

		
	js = json.dumps(userinfo)
	resp = Response(js, status=HTTP_CODE_OK, mimetype='application/json')
	return resp

def logout_api():
	# refresh_token = get_refreshtoken()
	refresh_token = request.values.get("token")
	keycloak_openid.logout(refresh_token)
		
	data = {
			'code' : HTTP_CODE_OK,
			'user message'  : 'User is logged out',
			'developer message' : 'User is logged out'
	}   
	js = json.dumps(data)
	resp = Response(js, status=HTTP_CODE_OK, mimetype='application/json')
	return resp

# retrieve the active state of a token
def refresh_token_api():
	refresh_token = request.values.get("token")
	try:
		new_token = keycloak_openid.refresh_token(refresh_token)
	except:
		data = {
			'code' : HTTP_CODE_UNAUTHORIZED,
			'user message'  : 'Session is not active',
			'developer message' : 'Session is not active'
		}   
		js = json.dumps(data)
		resp = Response(js, status=HTTP_CODE_UNAUTHORIZED, mimetype='application/json')
		return resp 
			
	js = json.dumps(new_token)
	resp = Response(js, status=HTTP_CODE_OK, mimetype='application/json')
	return resp

def instropect_accesstoken_api():
	access_token = request.values.get("token")
	try:
		token_info = keycloak_openid.introspect(access_token)
	except Exception as e:
		data = {
			'code' : HTTP_CODE_BAD_REQUEST,
			'user message'  : 'Invalid token',
			'developer message' : 'Invalid token'
		}   
		js = json.dumps(data)
		resp = Response(js, status=HTTP_CODE_BAD_REQUEST, mimetype='application/json')
		return resp 
		
	js = json.dumps(token_info)
	resp = Response(js, status=HTTP_CODE_OK, mimetype='application/json')
	return resp

def set_admin_api():
	url = request.values.get("server")
	name = request.values.get("name")
	password = request.values.get("password")
 	realm = request.values.get("realm")

 	global keycloak_admin
	keycloak_admin = KeycloakAdmin(server_url=url,username=name,password=password,realm_name=realm,verify=True)

	data = {
			'code' : HTTP_CODE_OK,
			'user message'  : 'set admin successfully',
			'developer message' : 'set admin successfully'
	}   
	js = json.dumps(data)
	resp = Response(js, status=HTTP_CODE_OK, mimetype='application/json')
	return resp

def create_user_api():
	email = request.values.get("email")
	username = request.values.get("username")
	password = request.values.get("password")
	firstname =request.values.get("firstname")
	lastname = request.values.get("lastname")
 	realmname = request.values.get("realm")
 	organization = request.values.get("org")
 	
	new_user = keycloak_admin.create_user({"email": email,
                    "username": username,
                    "enabled": True,
                    "firstName": firstname,
                    "lastName": lastname,
                    "credentials": [{"value": password,"type": "password",}],
                    "realmRoles": ["user_default", ],
                    "attributes": {"organization": organization}})
	data = {
			'code' : HTTP_CODE_OK,
			'user message'  : 'Created user successfully',
			'developer message' : 'Created user successfully'
	}   
	js = json.dumps(data)
	resp = Response(js, status=HTTP_CODE_OK, mimetype='application/json')
	return resp  
'''
def retrieve_all_users_api():
	users = keycloak_admin.get_users({})
	js = json.dumps(users)
	resp = Response(js, status=HTTP_CODE_BAD_OK, mimetype='application/json')
	return resp  
'''

def retrieve_user_by_username_api():
	username = request.values.get("username")
	user_id_keycloak = keycloak_admin.get_user_id(username)

	user = keycloak_admin.get_user(user_id_keycloak)
	print user
	
	data = {
		'code' : HTTP_CODE_OK,
		'user message'  : 'Retrieve user successfully',
		'developer message' : 'Retrieve user successfully'
	} 
	js = json.dumps(user)
	resp = Response(js, status=HTTP_CODE_OK, mimetype='application/json')
	return resp

	
def update_user_by_username_api():
	#username = request.values.get("username")
	payload = request.query_string
	#print payload
	#payload_json = request.json
	payload_json = jsonurl.parse_query(payload)
	#print payload_json
	#print payload_json
	username = payload_json['username']
	user_id_keycloak = keycloak_admin.get_user_id(username)
	keycloak_admin.update_user(user_id=user_id_keycloak,
                                      payload=payload_json)
	data = {
			'code' : HTTP_CODE_OK,
			'user message'  : 'Update user successfully',
			'developer message' : 'Update user successfully'
	}   
	js = json.dumps(data)
	resp = Response(js, status=HTTP_CODE_UNAUTHORIZED_OK, mimetype='application/json')
	return resp

def generate_passwd():
	"""[summary]
	The function randomly generates a password.
	[description]
	This function generates randomly a password from ascii letters and digits. The length of password is limitted from PASSWD_MIN_LEN to PASSWD_MAX_LEN
	
	Returns:
		[type: String] -- [description: a generated password]
	"""
	characters = string.ascii_letters + string.digits # + string.punctuation
	passwd =  "".join(choice(characters) for x in range(randint(PASSWD_MIN_LEN, PASSWD_MAX_LEN)))
	return passwd

def reset_user_password_by_username_api():
	username = request.values.get("username")
	user_id_keycloak = keycloak_admin.get_user_id(username)
	
	temppwd = generate_passwd()
	response = keycloak_admin.set_user_password(user_id=user-id-keycloak, password=temppwd, temporary=True)
 	data = {
			'code' : HTTP_CODE_OK,
			'user message'  : temppwd,
			'developer message' : temppwd
	}   
	js = json.dumps(data)
	resp = Response(js, status=HTTP_CODE_OK, mimetype='application/json')
	return resp

def delete_user_api():
	username = request.values.get("username")
	user_id_keycloak = keycloak_admin.get_user_id(username)
	response = keycloak_admin.delete_user(user_id=user_id_keycloak)
	data = {
			'code' : HTTP_CODE_OK,
			'user message'  : 'Delete user successfully',
			'developer message' : 'Delete user successfully'
	}   
	js = json.dumps(data)
	resp = Response(js, status=HTTP_CODE_OK, mimetype='application/json')
	return resp  
#validate user
#user management
#dynamic registration
#roles management

def create_client_api():
	payload = request.query_string
	payload_json = jsonurl.parse_query(payload)
	#payload_json = request.data
	#print payload_json
	#print payload_json2
	#payload_json3 = {"client_name":"app7"}

	#headers = request.headers
	#headers = {"Authorization":"Bearer eyJhbGciOiJSUzI1NiIsImtpZCIgOiAiR0RhdkZ5V1l5QXdrVkRQaVhRVWZxbHU2SVY4cTJXV2VTUUNqa2ltVktUSSJ9.eyJqdGkiOiJiZDk2NWNmZi01N2Q2LTQxOWUtOTAyNC0wMTRlMTExYTRiNzIiLCJleHAiOjE1MzYxNjAyMzksIm5iZiI6MCwiaWF0IjoxNTM1NzI4MjM5LCJpc3MiOiJodHRwOi8vMzEuMTcxLjI0Ni4xODc6ODA4MC9hdXRoL3JlYWxtcy9yZWFsbTAxIiwiYXVkIjoiaHR0cDovLzMxLjE3MS4yNDYuMTg3OjgwODAvYXV0aC9yZWFsbXMvcmVhbG0wMSIsInR5cCI6IkluaXRpYWxBY2Nlc3NUb2tlbiJ9.gE7MT0eYOBJL3SyOHc9WfDqeHGKdDqakkAoET6lgtvD7yTHECu-OLLaBePgCpAsw9pFvJgzb2McDUYtFNYJvWSzXOuauYtKF5hkQWsnakHAd-d_Uwagu0f8Hp7eZi5wQkSskal-xwpOlL9H_gZxCTK7PaOVdURiIBlcPHte6zlbU25GxC_aC3Dw1-aDHDwFCPw-TzfxMRZccWDkNfAFeA9BKSYe03JxvGG-OEVYA0mNuONjcW5vDMyNafzp6b3QP6t38-PfU7uwfwIn0lOSQi6-AGrDYhU62hl_5dEZW96cmRhEHXu2nlsQrTM4NjZIMLAFYefYdoa8Lxrto5TEedg"}
	headers = {"Authorization":dict(request.headers)['Authorization']}
	#print dict(request.headers)['Authorization']
	#print registration_endpoint
	#print payload_json
	r = requests.post("http://31.171.246.187:8080/auth/realms/realm01/clients-registrations/openid-connect", json = payload_json, headers=headers)
	print(r.status_code, r.reason)

	data = {
			'code' : HTTP_CODE_OK,
			'user message'  : "create client successfully",
			'developer message' : "create client successfully"
	}   
	js = json.dumps(data)
	resp = Response(js, status=HTTP_CODE_OK, mimetype='application/json')
	return resp

#curl -X POST -d '{ "client_name": "app05" }' -H "Content-Type:application/json" -H "Authorization: bearer eyJhbGciOiJSUzI1NiIsImtpZCIgOiAiR0RhdkZ5V1l5QXdrVkRQaVhRVWZxbHU2SVY4cTJXV2VTUUNqa2ltVktUSSJ9.eyJqdGkiOiIwMDM5Njk3OS1jOGNlLTRmMjMtYTg0Yi0xNjIzM2VhOTcwZjUiLCJleHAiOjE1MzU4OTk4NjMsIm5iZiI6MCwiaWF0IjoxNTM1NzI3MDYzLCJpc3MiOiJodHRwOi8vMzEuMTcxLjI0Ni4xODc6ODA4MC9hdXRoL3JlYWxtcy9yZWFsbTAxIiwiYXVkIjoiaHR0cDovLzMxLjE3MS4yNDYuMTg3OjgwODAvYXV0aC9yZWFsbXMvcmVhbG0wMSIsInR5cCI6IkluaXRpYWxBY2Nlc3NUb2tlbiJ9.bD6NQYqbuoVjgFFljfQZqesPkgEFN_tPSn0ywh0ZugDtRYcvv4vc1nOdUmYiNbVz3rdLNtLtlNuv59H9qyOnA1dp3iHiJXVyGHHlJAT7TxOXPXQnn4PvvCj0P_kpottr1HYEhVC6hBpwQxg6t5FB82QdOQevGAkCP68sIVsM3BJ0t22dDs7rLYiRzzAEnkyXvRUwJy8FUdMlWIHG6yupsyHTe33sTbo2TinXSSImuEWq5Sq-NgUm2YQuywaZTXHFxrmtNY7DdQMTG_rbulDAfMJqq2iWKSLbRo3lnAozGgKwKySMyLUOO39BZrLM_I3ODUYwxMOXFuOB0XR985x-sw" http://31.171.246.187:8080/auth/realms/realm01/clients-registrations/openid-connect