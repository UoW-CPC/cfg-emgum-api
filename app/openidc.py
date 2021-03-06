# Update on 16:00, 10.10.2018
from flask import Flask
from flask import jsonify, abort, Response
from flask_restful import request, reqparse, fields, marshal, Resource
import os
import json
import csv
import string
import requests
import logging
#import jsonurl
from app import app
import random
from random import randint
from parameters import keycloak_server, keycloak_realm, ssl_key, ssl_cert
#from posix import access

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

logger = logging.getLogger(__name__)

##### GLOBAL CONFIGURATION AND VARIABLES
cfg_path = os.path.abspath(os.path.join(os.path.dirname(__file__),".."))

# import the resource of all messages
csv_path = os.path.join(cfg_path, 'resource.csv')
reader = csv.DictReader(open(csv_path, 'r'))
msg_dict = {}
for row in reader:
    msg_dict[row['Code']] = row['Message']
##### END - GLOBAL CONFIGURATION AND VARIABLES


##### INTERNAL FUNCTIONS
def create_json_response(http_code, message_label, info_for_developer="", additional_json = {}):
    logger.info("Creating json response: \n http_code => {0} \nmessage_label => {1} \nmessage_label_value => {2} \ninfo_for_developer => {3} \ninfo_for_developer => {4}" \
        .format(http_code,message_label,msg_dict[message_label],info_for_developer,additional_json))
    data = {
        'code' : http_code,
        'message'  : msg_dict[message_label] + info_for_developer
    }
    data.update(additional_json)   
    js = json.dumps(data)
    resp = Response(js, status=http_code, mimetype='application/json')
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
    #    'roles': fields.List(fields.String)
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
        headers = {"Authorization":auth}
        clients_link = keycloak_server + "realms/" + keycloak_realm + "/clients-registrations/openid-connect/" + client_id

        logger.debug("RETRIEVE A CLIENT")
        logger.debug("headers: ", headers)
        logger.debug("clients_link: ", clients_link)
        logger.debug("client_id: ", client_id)

        received_response = False
        try:
            r = requests.get(clients_link, headers=headers,cert =(ssl_cert,ssl_key))
            client = r.json()

            received_response = True 

            client_filtered = dict(marshal(client, client_model_view))

            logger.debug("client: ", client)
            logger.debug("filtered client: ", client_filtered)

            client_id = client['client_id']    # if r returns error, client['client_id'] does not exist
            resp = create_json_response(HTTP_CODE_OK,'retrieve_client_successful', additional_json=client)
            return resp    
        except Exception as e:
            logger.error(e)
            if(received_response):
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'retrieve_client_failed', additional_json = client)
            else:
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'retrieve_client_failed')
            return resp
        

    def put(self,client_id):
        json_body = request.json
        
        auth = request.headers.get('authorization')
        headers = {"Authorization":auth}
                
        clients_link = keycloak_server + "realms/" + keycloak_realm + "/clients-registrations/openid-connect/" + client_id
        
        json_body.update({'client_id' : client_id}) # Keycloak REST API requires client_id in json_body; therefore, we add this information here        
        
        logger.debug("UPDATE CLIENT")
        logger.debug("json_body: ", json_body)
        logger.debug("headers: ", headers)
        logger.debug("clients_link: ", clients_link)

        
        try:
            r = requests.put(clients_link, json = json_body, headers=headers,cert =(ssl_cert,ssl_key))

            filtered_response = dict(marshal(json.loads(r.text), client_model_view)) # filter the response to match with client_model_view
            filtered_none_response = dict(filter(lambda item: item[1] is not None, filtered_response.items())) # remove all fields with value None

            logger.debug("response: ", r.status_code)
            logger.debug("updated client info: ", r.text)
            logger.debug("filtered updated client info: ", filtered_none_response)

            if r.status_code == HTTP_CODE_OK:
                resp = create_json_response(HTTP_CODE_OK,'update_client_successful',additional_json=filtered_none_response)
            else:
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'fail_to_update_client')

            return resp
        except Exception as e:
            logger.error(e) 
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'fail_to_update_client')
            return resp

    def delete(self,client_id):
        auth = request.headers.get('authorization')
        headers = {"Authorization":auth}
        

        clients_link = keycloak_server + "realms/" + keycloak_realm + "/clients-registrations/openid-connect/" + client_id

        logger.debug("DELETE CLIENT")
        logger.debug("headers: ", headers)
        logger.debug("client_id: ", client_id)
        logger.debug("clients_link: ", clients_link)

        try:        
            r = requests.delete(clients_link, headers=headers,cert =(ssl_cert,ssl_key))
            resp = create_json_response(HTTP_CODE_OK,'delete_client_successful')
            return resp
        except Exception as e:
            logger.error(e) 
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

        auth = request.headers.get('authorization')
        headers = {"Authorization":auth}
        #r = "http://<IP address of keycloak server>:8080/auth/realms/<realm name>/clients-registrations/openid-connect"
        request_link = keycloak_server + "realms/" + keycloak_realm + "/clients-registrations/openid-connect"

        logger.debug("CREATE CLIENT")
        logger.debug("request link: ",request_link)
        logger.debug("headers: ",headers)
        logger.debug("json_body: ",json_body)

        # Send a request to keycloak server to dynamically register as keycloak client
        try:
            r = requests.post(request_link, json = json_body, headers=headers,cert =(ssl_cert,ssl_key))
            response = r.json()

            logger.debug("response: ",response)
            logger.debug("status code: ",r.status_code)

            if(r.status_code==HTTP_CODE_CREATED):
                resp = create_json_response(HTTP_CODE_OK,'register_client_success',additional_json=response)
            else:
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'register_client_failed',additional_json=response)
            return resp
        except Exception as e:
            logger.error(e) 
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'register_client_failed')
            return resp
### END - CLIENT

### TOKEN
class Token(Resource):
    def put(self,token): # refresh/ renew access token. Token = refresh token
        json_body = request.json
        client_id = json_body ['client_id']
        client_secret = json_body ['client_secret']

        logger.debug("RENEW TOKENS")
        logger.debug("json body: ", json_body)

        try:
            token_link = keycloak_server + "realms/" + keycloak_realm + "/protocol/openid-connect/token"
            payload = {"client_id":client_id, "client_secret": client_secret, "refresh_token": token, "grant_type":"refresh_token"} 
            r = requests.post(token_link,data=payload,cert =(ssl_cert,ssl_key)) # data is in x-www-form-urlencoded
            new_token  = r.json()
           
            logger.debug('new token: ', new_token)   
                     
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
            token_link = keycloak_server + "realms/" + keycloak_realm + "/protocol/openid-connect/logout"
            payload = {"client_id":client_id, "client_secret": client_secret, "refresh_token": token} 
            r = requests.post(token_link,data=payload,cert =(ssl_cert,ssl_key)) # data is in x-www-form-urlencoded
            
            resp = create_json_response(HTTP_CODE_OK,'succeed_to_log_out')
            
            logger.debug("DELETE TOKENS")         

            return resp
        except Exception as e:
            logger.error(e)
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
            token_link = keycloak_server + "realms/" + keycloak_realm + "/protocol/openid-connect/token/introspect"
            payload = {"client_id":client_id, "client_secret": client_secret, "token": token} 
            r = requests.post(token_link,data=payload,cert =(ssl_cert,ssl_key)) # data is in x-www-form-urlencoded
            token_info  = r.json()
            filtered_token_info = dict(marshal(token_info,token_verification_view))
            
            logger.debug("VERIFY TOKEN")
            logger.debug("token info: ", token_info)
            logger.debug("filtered token info: ", filtered_token_info)
            
            if token_info["active"]: # token is valid
                resp = create_json_response(HTTP_CODE_OK,'valid_token',additional_json=token_info)
            else: # token is not valid
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'invalid_token')
            return resp
        except Exception as e:
            logger.error(e)
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'invalid_token')
            return resp
    def post(self,token):  # exchange token
        grant_type = "urn:ietf:params:oauth:grant-type:token-exchange"
        requested_token_type = "urn:ietf:params:oauth:token-type:refresh_token"
        
        json_body = request.json
        
        try:
            client_id = json_body ['client_id']
            client_secret = json_body ['client_secret']
        except Exception as e:
            logger.error(e) 
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'fail_to_exchange_token', additional_json={"error" : "invalid json parameters"})
            return resp
        
        try: # if "scope" is included in the request
            scope = json_body ['scope']
            payload = {"client_id":client_id, "client_secret": client_secret, "scope": scope,"grant_type":grant_type, "requested_token_type":requested_token_type,"subject_token":token} 
        except Exception as e:
            payload = {"client_id":client_id, "client_secret": client_secret, "grant_type":grant_type, "requested_token_type":requested_token_type,"subject_token":token} 

        token_link = keycloak_server + "realms/" + keycloak_realm + "/protocol/openid-connect/token"

        logger.debug('EXCHANGE TOKENS')
        logger.debug("json body: ", json_body)

        try:
            r = requests.post(token_link,data=payload,cert =(ssl_cert,ssl_key)) # data is in x-www-form-urlencoded
            response  = r.json()

            logger.debug("Response:",response)
            
            if (r.status_code == HTTP_CODE_OK):
                resp = create_json_response(HTTP_CODE_OK,'succeed_to_exchange_token', additional_json=response)
            else:
                resp = create_json_response(r.status_code,'fail_to_exchange_token',additional_json=response)
            return resp
        except Exception as e:
            logger.error(e) 
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'fail_to_exchange_token', additional_json=response)
            return resp
        
class Tokens(Resource):
    def post(self): #  retrieve access and refresh token from user's username and password. Only client allowed for direct access grants could request
        logger.debug("retrieve tokens")
        json_body = request.json
        
        try:
            type = json_body['grant_type']
            client_id = json_body ['client_id']
            client_secret = json_body ['client_secret']
            if(type=='password'):
                username = json_body ['username']
                password = json_body ['password']
                payload = {"grant_type":type, "client_id": client_id, "client_secret":client_secret,"username":username,"password":password}
            else:
                payload = {"grant_type":type, "client_id": client_id, "client_secret":client_secret}
    
            token_link = keycloak_server + "realms/" + keycloak_realm + "/protocol/openid-connect/token"
            
            r = requests.post(token_link,data=payload,cert =(ssl_cert,ssl_key)) # data is in x-www-form-urlencoded
            response  = r.json()
            resp = create_json_response(HTTP_CODE_OK,'succeed_to_get_tokens',additional_json=response)
            return resp
        except Exception as e:
            logger.error(e) 
            resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'fail_to_get_tokens')
            return resp
### END - TOKEN

### USERINFO
class UserInfo(Resource):
    def get(self,token): # get user information. Token = access token.
        try:
            userinfo_link = keycloak_server + "realms/" + keycloak_realm + "/protocol/openid-connect/userinfo"
            logger.debug("userinfo link:",userinfo_link)
            
            access_token = "Bearer " + token
            headers = {"Authorization": access_token}
           
            r = requests.get(userinfo_link,headers=headers,cert =(ssl_cert,ssl_key))
            logger.debug("response:",r.text)
            userinfo = r.json()
            
            logger.debug('\nRETRIEVE USER INFORMATION: ')

            resp = create_json_response(HTTP_CODE_OK,'succeed_to_get_user_info',additional_json=userinfo)
            return resp
        except Exception as e:
            logger.error(e)
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
        
        access_token = request.headers.get('authorization')

        logger.debug('\nCREATE USER')
        logger.debug('user name: ', username)
        logger.debug('email: ', email)
        
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

            #access_token = retrieve_realm_admin_access_token()

            logger.debug('super user access token: ', access_token)

            create_user_link = keycloak_server + "admin/realms/" + keycloak_realm + "/users"
            
            headers = {'Authorization': access_token}

            r = requests.post(create_user_link,json=new_user,headers=headers,cert =(ssl_cert,ssl_key))

            logger.debug('response: ', r.status_code, '-', r.text)

            if r.status_code == HTTP_CODE_CREATED:
                resp = create_json_response(HTTP_CODE_CREATED,'create_user_successful')
            elif r.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'create_user_failed',info_for_developer="Please ensure that the provided access token is valid")
            elif r.status_code == HTTP_CODE_CONFLICT:
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'create_user_failed', info_for_developer = "Email existed")
            else:
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'create_user_failed', info_for_developer =" Please check if the provided access token is of the user with \'manage-user\' role")
            return resp
        except Exception as e:
            logger.error(e)
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'create_user_failed',additional_json=r)
            return resp
### END - USERINFO

### USER : these APIs work only if the provided access token is of a user with user_manager role
class User(Resource):
    def get(self,username): # retrieve user
        users_link = keycloak_server + "admin/realms/" + keycloak_realm + "/users"
        access_token = request.headers.get('authorization')

        try:
            headers = {'Authorization': access_token}

            search_criteria = {
                "username" : username
            }

            r = requests.get(users_link,params=search_criteria,headers=headers,cert =(ssl_cert,ssl_key))

            logger.debug('RETRIEVE A USER')
            logger.debug("response:",r)
                

            if r.status_code == HTTP_CODE_OK:
                ret  = r.json()
                if ret!=[]:
                    response = ret[0]
                    #filtered_response = dict(marshal(response, user_model_view))
                    #logger.debug('Filtered user info:', filtered_response)
                    resp = create_json_response(HTTP_CODE_OK,"retrieve_user_successful",additional_json=response)
                else:
                    resp = create_json_response(HTTP_CODE_OK,"retrieve_user_successful",additional_json={"firstName":"The user does not exist"})
            elif r.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'retrieve_user_failed',info_for_developer="Please ensure that the provided access token is valid")
            else:
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'retrieve_user_failed', info_for_developer =" Please check if the provided access token is of the user with \'manage-user\' role")
            
            return resp   

        except Exception as e:
            logger.error(e)
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,"retrieve_user_failed",additional_json=r)
            return resp

    def put(self,username): # update user
        users_link = keycloak_server + "admin/realms/" + keycloak_realm + "/users/" 
        json_body = request.json

        new_user_info = dict(marshal(json_body,user_model_update))
        
        access_token = request.headers.get('authorization')
        
        logger.info('\nUPDATE USER')
        logger.info('Json body => {0}'.format(json_body))
        logger.info('New user info => {0}'.format(new_user_info))
        #logger.info('access token:', access_token)    

        try:
            #access_token = retrieve_realm_admin_access_token()
            headers = {'Authorization': access_token}

            search_criteria = {
                "username" : username
            }

            r = requests.get(users_link,params=search_criteria,headers=headers,cert =(ssl_cert,ssl_key))
            if r.status_code == HTTP_CODE_OK:
                ret  = r.json()
                if ret!=[]: 
                    user_id  = r.json()[0]['id']
                    update_users_link = users_link + user_id
        
                    r = requests.put(update_users_link,json=new_user_info,headers=headers,cert =(ssl_cert,ssl_key))
        
                    resp = create_json_response(HTTP_CODE_OK,"update_user_successful")
                else:
                    resp = create_json_response(HTTP_CODE_OK,"update_user_successful",additional_json={"Details":"The user does not exist"})
            elif r.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'retrieve_user_failed',info_for_developer="Please ensure that the provided access token is valid")
            else:
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'retrieve_user_failed', info_for_developer =" Please check if the provided access token is of the user with \'manage-user\' role")
            
            return resp
        except Exception as e:
            logger.error(e)
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,"update_user_failed",additional_json=r)
            return resp
    def delete(self,username): # delete user
        users_link = keycloak_server + "admin/realms/" + keycloak_realm + "/users/" 
        access_token = request.headers.get('authorization')
        try:
            #access_token = retrieve_realm_admin_access_token()
            headers = {'Authorization': access_token}

            search_criteria = {
                "username" : username
            }
            r = requests.get(users_link,params=search_criteria,headers=headers,cert =(ssl_cert,ssl_key))
            if r.status_code == HTTP_CODE_OK:
                ret  = r.json()
                if ret!=[]: 
                    user_id  = r.json()[0]['id']

                    delete_users_link = users_link + user_id
                    logger.debug("delete user link:",delete_users_link)
                    r = requests.delete(delete_users_link,headers=headers,cert =(ssl_cert,ssl_key))

                    resp = create_json_response(HTTP_CODE_OK,"delete_user_successful")
                else:
                    resp = create_json_response(HTTP_CODE_OK,"delete_user_successful",additional_json={"Details":"The user does not exist"})
            elif r.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'delete_user_failed',info_for_developer="Please ensure that the provided access token is valid")
            else:
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'delete_user_failed', info_for_developer =" Please check if the provided access token is of the user with \'manage-user\' role")
        
            return resp  
        except Exception as e:
            logger.error(e)
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,"delete_user_failed",additional_json=r)
            return resp
### END - USER

### UserGroups
class UserGroups(Resource):
    def get_user_id(self,access_token,username):
        user_id = ""
        users_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/users?username=" + username 
        headers = {'Authorization': access_token}
        r = requests.get(users_api_url,headers=headers,cert =(ssl_cert,ssl_key))
        logger.debug("Get user id response. \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
        if r.status_code == HTTP_CODE_OK:
            ret  = r.json()
            if ret!=[]: 
                user_id  = r.json()[0]['id']
        return user_id,r
    def get_user_group(self,access_token,user_id):
        logger.debug("Get user group")
        access_token = request.headers.get('authorization')
        user_groups_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/users/" + user_id + "/groups"
        headers = {'Authorization': access_token}
        grp_result = requests.get(user_groups_api_url,headers=headers,cert =(ssl_cert,ssl_key))
        logger.info("User groups response. \n status_code => {0} \n response_message => {1}".format(grp_result.status_code,grp_result.text))
        if grp_result.status_code == HTTP_CODE_OK:
            userGrps = grp_result.json()
            for grp in userGrps:
                grp_id = grp["id"]
                grp_name = grp["name"]
                group_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/groups/" + grp_id
                r = requests.get(group_api_url,headers=headers,cert =(ssl_cert,ssl_key))
                logger.info("Get group server response: \n response code => {0} \n returned message => {1}".format(r.status_code, r.text))
                if r.status_code == HTTP_CODE_OK:
                    groupResult = r.json()
                    grp_attributes = groupResult["attributes"]
                else:
                    grp_attributes = {}
                return grp_id,grp_name,grp_attributes,grp_result
        return "","",{},grp_result
    def get_group_admin_members(self,access_token,grp_id):
        logger.debug("Get group admin members")
        access_token = request.headers.get('authorization')
        group_members_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/groups/" + grp_id + "/members"
        headers = {'Authorization': access_token}
        mem_result = requests.get(group_members_api_url,headers=headers,cert =(ssl_cert,ssl_key))
        logger.info("Group's members response. \n status_code => {0} \n response_message => {1}".format(mem_result.status_code,mem_result.text))
        lst_admin_members = []
        if mem_result.status_code == HTTP_CODE_OK:
            grpMembers = mem_result.json()
            for member in grpMembers:
                member_id = member["id"]
                roles_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/users/" + member_id + "/role-mappings/realm"
                r = requests.get(roles_api_url,headers=headers,cert =(ssl_cert,ssl_key))
                logger.info("Get roles server response: \n response code => {0} \n returned message => {1}".format(r.status_code, r.text))
                if r.status_code == HTTP_CODE_OK:
                    roleResult = r.json()
                    for role in roleResult:
                        role_name = role["name"]
                        if role_name.lower() == "org_admin" or role_name.lower() == "org_owner":
                            memberDict = {}
                            memberDict["username"] = member["username"]
                            memberDict["firstName"] = member["firstName"]
                            memberDict["lastName"] = member["lastName"]
                            memberDict["email"] = member["email"]
                            memberDict["enabled"] = member["enabled"]
                            lst_admin_members.append(memberDict)
                            break
        return lst_admin_members, mem_result
    def get(self,username):
        try:
            logger.debug("Get user ({0}) groups".format(username))
            access_token = request.headers.get('authorization')
            # Get user id for the given username
            user_id, res_user = self.get_user_id(access_token,username)
            if res_user.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'user_group_retreival_failed',info_for_developer=" Please ensure that the provided access token is valid")
                return resp
            if user_id == "":
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'user_group_retreival_failed', info_for_developer =" User with given name does not exist.")
                return resp
            # Get User's group 
            grp_id, grp_name, grp_attributes, grp_result = self.get_user_group(access_token,user_id)
            if grp_result.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'user_group_retreival_failed',info_for_developer=" Please ensure that the provided access token is valid")
                return resp
            if grp_id == "":
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'user_group_retreival_failed', info_for_developer=" The specified user does not belong to any organisation/group")
                return resp
            # Get admin/owner members of user's group
            adminsList, mem_result = self.get_group_admin_members(access_token,grp_id)
            if mem_result.status_code == HTTP_CODE_OK:
                grpDict = {}
                grpDict["name"] = grp_name
                grpDict["attributes"] = grp_attributes
                grpDict["admins"] = adminsList
                resp = create_json_response(HTTP_CODE_OK,'user_group_retreival_successful', additional_json=grpDict)
                return resp
            else:
                resp = create_json_response(mem_result.status_code,'user_group_retreival_failed', info_for_developer=mem_result.text)
                return resp
        except Exception as e:
            logger.error("Exception occured during the processing of group assignment request. The details of the exception are as follows: \n {0}".format(e))
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'group_creation_failed',additional_json=e)
            return resp
### ENDPOINT
class Endpoint(Resource):
    def get(self): # return endpoint of public key
        endpoint = keycloak_server + "realms/" + keycloak_realm + "/protocol/openid-connect/certs"
        epJson = {'pk_endpoint':endpoint}
        resp = create_json_response(HTTP_CODE_OK,'endpoint_successful',additional_json=epJson)
        return resp
### END - ENDPOINT

### RPT (Relying party token)
class Rpt(Resource):
    def post(self): # retrieve rpt token
        logger.info("Retrieve rpt token")
        json_body = request.json
        logger.debug("json:",json_body)
        try:
            rs_id = json_body ['resource_server_id']
            resource = json_body ['resource_name']
        except Exception as e:
            logger.error(e) 
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'fail_to_get_rpt', additional_json={"error" : "invalid json parameters"})
            return resp
                
        rs_scope = resource # + "#" + scope
        payload = {"audience":rs_id, "permission": rs_scope, "grant_type":"urn:ietf:params:oauth:grant-type:uma-ticket"} 
        
        access_token = request.headers.get('authorization')
        headers = {"Authorization":  access_token}

        token_link = keycloak_server + "realms/" + keycloak_realm + "/protocol/openid-connect/token"
        
        logger.debug('RETRIEVE RPT TOKEN')
        logger.debug("json body: ", json_body)
        logger.debug("Access token:", access_token)


        try: 
            r = requests.post(token_link,headers=headers,data=payload,cert =(ssl_cert,ssl_key)) # data is in x-www-form-urlencoded
            response  = r.json()

            logger.debug("Response:",response)
                
            if r.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'fail_to_get_rpt',additional_json=response)
                return resp

            rpt = response['access_token']

            logger.debug("Tokens: ", rpt)


            resp = create_json_response(HTTP_CODE_OK,'succeed_to_get_rpt',additional_json={"rpt token":rpt})
            return resp
        except Exception as e:
            logger.error(e) 
            resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'fail_to_get_rpt')#, additional_json=e)#{"error description":"Please view the log file"})
            return resp
        
class RptToken(Resource):
    def post(self,token): #introspect RPT token
        json_body = request.json
        try:
            client_id = json_body ['client_id']
            client_secret = json_body ['client_secret']    
        except Exception as e:
            logger.error(e) 
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'fail_to_verify_rpt', additional_json={"error" : "invalid json parameters"})
            return resp

        logger.debug('INTROSPECT RPT TOKENS')
        token_link = keycloak_server + "realms/" + keycloak_realm + "/protocol/openid-connect/token/introspect"
        
        try:    
            payload = {"token_type_hint":"requesting_party_token","token":token}
            r = requests.post(token_link,auth=(client_id,client_secret),data=payload,cert =(ssl_cert,ssl_key)) # data is in x-www-form-urlencoded
            token_rpt_info  = r.json()

            logger.debug("Response:",token_rpt_info)

            if (token_rpt_info['active']):
                resp = create_json_response(HTTP_CODE_OK,'succeed_to_verify_rpt', additional_json=token_rpt_info)
            else:
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'fail_to_verify_rpt', additional_json=token_rpt_info)
            return resp
        except Exception as e:
            logger.error(e) 
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'fail_to_verify_rpt', additional_json={"error":"Invalid client_id/ client_secret"})
            return resp
### END - RPT

### Groups
class Groups(Resource):
    def get(self):
        try:         
            access_token = request.headers.get('authorization')
            logger.info("Get groups")
            api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/groups"
            headers = {'Authorization': access_token}
            r = requests.get(api_url,headers=headers,cert =(ssl_cert,ssl_key))
            logger.info("Server response: \n response code => {0} \n returned message => {1}".format(r.status_code, r.text))
            if r.status_code == HTTP_CODE_OK:
                allGroups = r.json()
                namesList = []
                for grp in allGroups:
                    namesList.append(grp["name"])
                grpDict = {}
                grpDict["groups"] = namesList
                resp = create_json_response(HTTP_CODE_OK,'groups_retreival_successful', additional_json=grpDict)
            elif r.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'groups_retreival_failed',info_for_developer=" Please ensure that the provided access token is valid")
            else:
                resp = create_json_response(r.status_code,'groups_retreival_failed',info_for_developer=r.text)
            return resp
        except Exception as e:
            logger.error("Exception occured during the processing of Groups Get request. The details of the exception are as follows: \n {0}".format(e))
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'groups_retreival_failed',additional_json=r)
            return resp
    def post(self):
        try:         
            json_body = request.json    
            access_token = request.headers.get('authorization')
            logger.info("Create group with input data => {0}".format(json_body))
            api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/groups"
            headers = {'Authorization': access_token}
            r = requests.post(api_url,json=json_body,headers=headers,cert =(ssl_cert,ssl_key))
            logger.info("Server response: \n response code => {0} \n returned message => {1}".format(r.status_code, r.text))
            if r.status_code == HTTP_CODE_CREATED:
                resp = create_json_response(r.status_code,'group_creation_message',info_for_developer="New group created successfuly.")
            elif r.status_code == HTTP_CODE_CONFLICT:
                resp = create_json_response(r.status_code,'group_creation_message',info_for_developer="Group with same name already exist.")
            else:
                resp = create_json_response(r.status_code,'group_creation_message',info_for_developer=r.text)
            return resp
        except Exception as e:
            logger.error("Exception occured during the processing of Groups post request. The details of the exception are as follows: \n {0}".format(e))
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'group_creation_failed',additional_json=r)
            return resp

class Group(Resource):
    def get_group_id(self,access_token,groupname):
        group_id = ""
        groups_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/groups?search=" + groupname
        headers = {'Authorization': access_token}
        r = requests.get(groups_api_url,headers=headers,cert =(ssl_cert,ssl_key))
        logger.info("Get group response. \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
        if r.status_code == HTTP_CODE_OK:
            result_json = r.json()
            for item in result_json:
                if item["name"] == groupname:
                    group_id = item["id"]
                    logger.info("Group search result => Group found and the id is => {0}".format(group_id))
                    break
        return group_id,r
    
    def get(self,groupname):
        try:         
            access_token = request.headers.get('authorization')
            logger.info("Get group")
            # Get group Id
            group_id, res_group = self.get_group_id(access_token,groupname)
            if res_group.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'group_retreival_successful',info_for_developer=" Please ensure that the provided access token is valid")
                return resp
            if group_id == "":
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'group_retreival_failed', info_for_developer =" Group with given name does not exist.")
                return resp
            api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/groups/" + group_id
            headers = {'Authorization': access_token}
            r = requests.get(api_url,headers=headers,cert =(ssl_cert,ssl_key))
            logger.info("Server response: \n response code => {0} \n returned message => {1}".format(r.status_code, r.text))
            if r.status_code == HTTP_CODE_OK:
                groupResult = r.json()
                grpDict = {}
                grpDict["name"] = groupResult["name"]
                grpDict["attributes"] = groupResult["attributes"]
                resp = create_json_response(HTTP_CODE_OK,'group_retreival_successful', additional_json=grpDict)
            else:
                resp = create_json_response(r.status_code,'group_retreival_failed',info_for_developer=r.text)
            return resp
        except Exception as e:
            logger.error("Exception occured during the processing of Group get request. The details of the exception are as follows: \n {0}".format(e))
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'group_retreival_failed',additional_json=r)
            return resp

    def put(self,groupname):
        try:         
            json_body = request.json
            access_token = request.headers.get('authorization')
            logger.info("Update group with input data => {0}".format(json_body))
            # Get group Id
            group_id, res_group = self.get_group_id(access_token,groupname)
            if res_group.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'group_update_failed',info_for_developer=" Please ensure that the provided access token is valid")
                return resp
            if group_id == "":
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'group_update_failed', info_for_developer =" Group with given name does not exist.")
                return resp
            api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/groups/" + group_id
            headers = {'Authorization': access_token}
            r = requests.put(api_url,json=json_body,headers=headers,cert =(ssl_cert,ssl_key))
            logger.info("Server response: \n response code => {0} \n returned message => {1}".format(r.status_code, r.text))
            if r.status_code == 204:
                resp = create_json_response(r.status_code,'group_update_message',info_for_developer=" Group updated successfuly.")
            else:
                resp = create_json_response(r.status_code,'group_update_failed',info_for_developer=r.text)
            return resp
        except Exception as e:
            logger.error("Exception occured during the processing of Group put request. The details of the exception are as follows: \n {0}".format(e))
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'group_update_failed',additional_json=r)
            return resp
### GroupUsers
class GroupMembers(Resource):
    def get_group_id(self,access_token,groupname):
        group_id = ""
        groups_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/groups?search=" + groupname
        headers = {'Authorization': access_token}
        r = requests.get(groups_api_url,headers=headers,cert =(ssl_cert,ssl_key))
        logger.info("Get group response. \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
        if r.status_code == HTTP_CODE_OK:
            result_json = r.json()
            for item in result_json:
                if item["name"] == groupname:
                    group_id = item["id"]
                    logger.info("Group search result => Group found and the id is => {0}".format(group_id))
                    break
        return group_id,r
    
    def get(self,groupname):
        try:         
            access_token = request.headers.get('authorization')
            logger.info("Get group members")
            # Get group Id
            group_id, res_group = self.get_group_id(access_token,groupname)
            if res_group.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'group_members_retreival_successful',info_for_developer=" Please ensure that the provided access token is valid")
                return resp
            if group_id == "":
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'group_members_retreival_failed', info_for_developer =" Group with given name does not exist.")
                return resp
            api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/groups/" + group_id + "/members"
            headers = {'Authorization': access_token}
            r = requests.get(api_url,headers=headers,cert =(ssl_cert,ssl_key))
            logger.info("Server response: \n response code => {0} \n returned message => {1}".format(r.status_code, r.text))
            if r.status_code == HTTP_CODE_OK:
                memberResults = r.json()
                membersList = []
                for member in memberResults:
                    memberDict = {}
                    memberDict["username"] = member["username"]
                    memberDict["firstName"] = member["firstName"]
                    memberDict["lastName"] = member["lastName"]
                    memberDict["email"] = member["email"]
                    memberDict["enabled"] = member["enabled"]
                    membersList.append(memberDict)
                membersDict = {}
                membersDict["members"] = membersList
                resp = create_json_response(HTTP_CODE_OK,'group_members_retreival_successful', additional_json=membersDict)
            else:
                resp = create_json_response(r.status_code,'group_members_retreival_failed',info_for_developer=r.text)
            return resp
        except Exception as e:
            logger.error("Exception occured during the processing of Group get request. The details of the exception are as follows: \n {0}".format(e))
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'group_members_retreival_failed',additional_json=r)
            return resp
### Users-Groups
class UsersGroups(Resource):
    def get_user_id(self,access_token,username):
        user_id = ""
        users_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/users?username=" + username 
        headers = {'Authorization': access_token}
        r = requests.get(users_api_url,headers=headers,cert =(ssl_cert,ssl_key))
        logger.info("Get user id response. \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
        if r.status_code == HTTP_CODE_OK:
            ret  = r.json()
            if ret!=[]: 
                user_id  = r.json()[0]['id']
        return user_id,r
    def get_group_id(self,access_token,groupname):
        group_id = ""
        groups_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/groups?search=" + groupname
        headers = {'Authorization': access_token}
        r = requests.get(groups_api_url,headers=headers,cert =(ssl_cert,ssl_key))
        logger.info("Get group response. \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
        if r.status_code == HTTP_CODE_OK:
            result_json = r.json()
            for item in result_json:
                if item["name"] == groupname:
                    group_id = item["id"]
                    logger.info("Group search result => Group found and the id is => {0}".format(group_id))
                    break
        return group_id,r
    def check_user_group_membership(self,access_token,user_id):
        logger.info("Checking user membership for user_id => {0}".format(user_id))
        access_token = request.headers.get('authorization')
        headers = {'Authorization': access_token}
        group_counts = 0
        groups_count_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/users/" + user_id + "/groups/count"
        headers = {'Authorization': access_token}
        r = requests.get(groups_count_api_url,headers=headers,cert =(ssl_cert,ssl_key))
        logger.info("user groups count response. \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
        if r.status_code == HTTP_CODE_OK:
            result_json = r.json()
            group_counts = int(result_json["count"])
        return group_counts,r
    # def check_user_membership_for_group(self,access_token,user_id,group_id):
    #     logger.info("Checking whether user => {0} is a member of group => {1}".format(user_id,group_id))
    #     access_token = request.headers.get('authorization')
    #     headers = {'Authorization': access_token}
    #     group_counts = 0
    #     groups_membership_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/users/" + user_id + "/groups"
    #     headers = {'Authorization': access_token}
    #     r = requests.get(groups_count_api_url,headers=headers)
    #     logger.info("user groups response. \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
    #     if r.status_code == HTTP_CODE_OK:
    #         result_json = r.json()
    #         group_counts = int(result_json["count"])
    #     return group_counts,r
    def assign_user_to_group(self,access_token,user_id,group_id):
        logger.info("Assigning user with id => {0} to group with id => {1}".format(user_id,group_id))
        access_token = request.headers.get('authorization')
        headers = {'Authorization': access_token}
        user_group__api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/users/" + user_id + "/groups/" + group_id
        headers = {'Authorization': access_token}
        r = requests.put(user_group__api_url,headers=headers,cert =(ssl_cert,ssl_key))
        logger.info("user to group assignment response => \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
        return r
    def put(self,username,groupname): # assign user to the group
        try:
            logger.info("Assign user => {0} to the group => {1}".format(username,groupname))
            access_token = request.headers.get('authorization')
            # Get user id for the given username
            user_id, res_user = self.get_user_id(access_token,username)
            # Get group id for the given groupname
            group_id, res_group = self.get_group_id(access_token,groupname)
            if res_user.status_code == HTTP_CODE_UNAUTHORIZED or res_group.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'group_assignment_failed',info_for_developer="Please ensure that the provided access token is valid")
                return resp
            if user_id == "" or group_id == "":
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'group_assignment_failed', info_for_developer =" User/Group with given name does not exist.")
                return resp
            # Check if user is already member of another group or not. User can only be member of one group
            groups_count, res_mem = self.check_user_group_membership(access_token,user_id)
            if res_mem.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'group_assignment_failed',info_for_developer="Please ensure that the provided access token is valid")
                return resp
            if groups_count > 0:
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'group_assignment_failed', info_for_developer=" The specified user is already member of {0} groups.".format(groups_count))
                return resp
            # assign user to group
            r = self.assign_user_to_group(access_token,user_id,group_id)
            if r.status_code == 204:
                disp_message = " The specified user: {0}, is successfully assigned to group {1}".format(username,groupname)
            else:
                disp_message = r.text
            resp = create_json_response(r.status_code,'group_assignment_message', info_for_developer=disp_message)
            return resp
        except Exception as e:
            logger.error("Exception occured during the processing of group assignment request. The details of the exception are as follows: \n {0}".format(e))
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'group_creation_failed',additional_json=e)
            return resp
    def delete(self,username,groupname): # un-assign user to the group
        try:
            logger.info("Un-assigned user => {0} from the group => {1}".format(username,groupname))
            access_token = request.headers.get('authorization')
            # Get user id for the given username
            user_id, res_user = self.get_user_id(access_token,username)
            # Get group id for the given groupname
            group_id, res_group = self.get_group_id(access_token,groupname)
            if res_user.status_code == HTTP_CODE_UNAUTHORIZED or res_group.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'group_un_assignment_failed',info_for_developer="Please ensure that the provided access token is valid")
                return resp
            if user_id == "" or group_id == "":
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'group_un_assignment_failed', info_for_developer =" User/Group with given name does not exist.")
                return resp
            delete_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/users/" + user_id + "/groups/" + group_id
            headers = {'Authorization': access_token}
            r = requests.delete(delete_api_url,headers=headers,cert =(ssl_cert,ssl_key))
            logger.info("unassigned group response: \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
            if r.status_code == 204:
                disp_message = " The group => {0} is unassigned from user => {1} ".format(groupname, username)
            else:
                disp_message = r.text
            resp = create_json_response(r.status_code,'group_unassigned_message', info_for_developer=disp_message)
            return resp
        except Exception as e:
            logger.error("Exception occured during the processing of group unassignment request. The details of the exception are as follows: \n {0}".format(e))
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'group_unassigned_message',additional_json=e)
            return resp
### END - Groups
class Roles(Resource):
    def get(self):
        try:
            roles_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/roles"
            access_token = request.headers.get('authorization')
            headers = {'Authorization': access_token}
            r = requests.get(roles_api_url,headers=headers,cert =(ssl_cert,ssl_key))
            logger.info("Get roles response. \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
            rolesList =[]
            rolesData = {
                'roles': rolesList
            }
            if r.status_code == HTTP_CODE_OK:
                result_json = r.json()
                for item in result_json:
                    rolesList.append(item["name"])
            resp = create_json_response(HTTP_CODE_OK,"retrieve_roles_successful",additional_json=rolesData)
            return resp
        except Exception as e:
            logger.error(e)
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,"retrieve_roles_failed",additional_json=r)
            return resp
class UserRoles(Resource):
    def get_user_id(self,access_token,username):
        user_id = ""
        users_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/users?username=" + username 
        headers = {'Authorization': access_token}
        r = requests.get(users_api_url,headers=headers,cert =(ssl_cert,ssl_key))
        logger.info("Get user id response. \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
        if r.status_code == HTTP_CODE_OK:
            ret  = r.json()
            if ret!=[]: 
                user_id  = r.json()[0]['id']
        return user_id,r
    def get(self,username):
        try:
            access_token = request.headers.get('authorization')
            # Get user id for the given username
            user_id, res_user = self.get_user_id(access_token,username)
            if res_user.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'retrieve_roles_failed',info_for_developer="Please ensure that the provided access token is valid")
                return resp
            if user_id == "":
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'retrieve_roles_failed', info_for_developer =" User with given name does not exist.")
                return resp
            api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/users/" + user_id + "/role-mappings/realm"
            headers = {'Authorization': access_token}
            r = requests.get(api_url,headers=headers,cert =(ssl_cert,ssl_key))
            logger.info("Get user role response: \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
            rolesList =[]
            rolesData = {
                'roles': rolesList
            }
            if r.status_code == HTTP_CODE_OK:
                result_json = r.json()
                for item in result_json:
                    rolesList.append(item["name"])
                resp = create_json_response(HTTP_CODE_OK,"retrieve_roles_successful",additional_json=rolesData)
            else:
                resp = create_json_response(HTTP_CODE_OK,"retrieve_roles_failed",additional_json=rolesData)
            return resp
        except Exception as e:
            logger.error("Exception occured. The details of the exception are as follows: \n {0}".format(e))
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'retrieve_roles_failed',additional_json=e)
            return resp

class UserRole(Resource):
    def get_user_id(self,access_token,username):
        user_id = ""
        users_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/users?username=" + username 
        headers = {'Authorization': access_token}
        r = requests.get(users_api_url,headers=headers,cert =(ssl_cert,ssl_key))
        logger.info("Get user id response. \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
        if r.status_code == HTTP_CODE_OK:
            ret  = r.json()
            if ret!=[]: 
                user_id  = r.json()[0]['id']
        return user_id,r
    def get_role_id(self,access_token,rolename):
        role_id = ""
        role_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/roles/" + rolename 
        headers = {'Authorization': access_token}
        r = requests.get(role_api_url,headers=headers,cert =(ssl_cert,ssl_key))
        logger.info("Get role id response. \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
        if r.status_code == HTTP_CODE_OK:
            result_json = r.json()
            if "id" in result_json.keys():
                role_id = result_json["id"]
                logger.info("Role search result => Role found and the id is => {0}".format(role_id))
        return role_id,r

    def post(self,username,rolename):   # assign role to user
        try:
            access_token = request.headers.get('authorization')
            # Get user id for the given username
            user_id, res_user = self.get_user_id(access_token,username)
            if res_user.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'role_grant_failed',info_for_developer="Please ensure that the provided access token is valid")
                return resp
            if user_id == "":
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'role_grant_failed', info_for_developer =" User with given name does not exist.")
                return resp
            role_id, res_role = self.get_role_id(access_token,rolename)
            if res_user.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'role_grant_failed',info_for_developer="Please ensure that the provided access token is valid")
                return resp
            if role_id == "":
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'role_grant_failed', info_for_developer =" Role with given name does not exist.")
                return resp
            api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/users/" + user_id + "/role-mappings/realm"
            headers = {'Authorization': access_token}
            roles = [{"id": role_id, "name": rolename}]
            r = requests.post(api_url,json=roles,headers=headers,cert =(ssl_cert,ssl_key))
            logger.info("Delete role response: \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
            if r.status_code == 204:
                disp_message = " The user: {0}, is granted the role of: {1}".format(username,rolename)
            else:
                disp_message = r.text
            resp = create_json_response(r.status_code,'role_grant_message', info_for_developer=disp_message)
            return resp
        except Exception as e:
            logger.error("Exception occured during the processing of role grant request. The details of the exception are as follows: \n {0}".format(e))
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'role_grant_message',additional_json=e)
            return resp
    def delete(self,username,rolename): # revoke role from user
        try:
            access_token = request.headers.get('authorization')
            # Get user id for the given username
            user_id, res_user = self.get_user_id(access_token,username)
            if res_user.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'role_revoke_failed',info_for_developer="Please ensure that the provided access token is valid")
                return resp
            if user_id == "":
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'role_revoke_failed', info_for_developer =" User with given name does not exist.")
                return resp
            role_id, res_role = self.get_role_id(access_token,rolename)
            if res_user.status_code == HTTP_CODE_UNAUTHORIZED:
                resp = create_json_response(HTTP_CODE_UNAUTHORIZED,'role_revoke_failed',info_for_developer="Please ensure that the provided access token is valid")
                return resp
            if role_id == "":
                resp = create_json_response(HTTP_CODE_BAD_REQUEST,'role_revoke_failed', info_for_developer =" Role with given name does not exist.")
                return resp
            api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/users/" + user_id + "/role-mappings/realm"
            headers = {'Authorization': access_token}
            roles = [{"id":role_id, "name": rolename}]
            r = requests.delete(api_url,json=roles,headers=headers,cert =(ssl_cert,ssl_key))
            logger.info("delete role response: \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
            if r.status_code == 204:
                disp_message = " The role => {0} is now revoked from user => {1} ".format(roles, username)
            else:
                disp_message = r.text
            resp = create_json_response(r.status_code,'role_revoke_message', info_for_developer=disp_message)
            return resp
        except Exception as e:
            logger.error("Exception occured during the processing of role revokation request. The details of the exception are as follows: \n {0}".format(e))
            resp = create_json_response(HTTP_CODE_BAD_REQUEST,'role_revoke_message',additional_json=e)
            return resp


##### END - RESOURCES

