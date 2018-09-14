# Component OIDC Client
Requirement: install python-keycloak, flask, flask_restful
> sudo su

> pip install python-keycloak flask flask_restful

How to use APIs:

- Get user information

GET http://[IP address of API server]:5001/v1.0/userinfo/<access_token>

- Verify access token and get its information (Instropect)

GET http://[IP address of API server]:5001/v1.0/tokens/<access_token>

with query parameters:

client_id: <id of client>

client_secret: <secret of client>

- Refresh tokens

PUT http://[IP address of API server]:5001/v1.0/tokens/<refresh_token>

with json data:

client_id: <id of client>

client_secret: <secret of client>

- Log out

DELETE http://[IP address of API server]:5001/v1.0/tokens/<refresh_token>

with json data:

client_id: <id of client>

client_secret: <secret of client>

- Retrieve tokens from username and password

POST http://[IP address of OIDC client]:5001/v1.0/tokens

with json data

{
  "username" : <user_name>,
  "password" : <password>,
  "client_id" : <id of client>,
  "client_secret" : <secret of client> 
}

- Dynamically register as Keycloak Client

POST http://[IP of API server]:5001/v1.0/clients

with Client Registration Token as Bearer Header

and json data

{
  "clientId" : "app01",
  "redirectUris" : ["localhost1","localhost2"]
}

- Delete an OIDC client 

DELETE http://[IP of API server]:5001/v1.0/clients/<id_of_client>

- Update an OIDC client

PUT http://[IP of API server]:5001/v1.0/clients/<id_of_client>

- Retrieve an OIDC client information

GET http://[IP of API server]:5001/v1.0/clients/<id_of_client>

- Create a user

POST http://[IP of API server]:5001/v1.0/users

with json data

{
	"username" : ,
	"password" : ,
	"firstname" : ,
	"lastname" : ",
	"organization" : ,
	"email" :
}

- Retrieve a user

GET http://[IP of API server]:5001/v1.0/users/<user name>

- Update a user

PUT http://[IP of API server]:5001/v1.0/users/<user name>

with json data

{
  "firstName" : ,
  "lastName" : 
}

- Delete a user

DELETE http://[IP of API server]:5001/v1.0/users/<user name>