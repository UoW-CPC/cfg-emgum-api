# Component OIDC Client
# Required packages:

Python-keycloak, flask, flask_restful

> sudo su

> pip install python-keycloak flask flask_restful

# How to use APIs:

The supported APIs:
* Create/ Retrieve/ Update/ Delete OIDC client(s)
* Retrieve/ Verify/ Renew/ Exchange tokens
* Log out
* Create/ Retrieve/ Update/ Delete user(s)
* Retrieve user information
* Retrieve public key
* Retrieve/ verify Relying Party Token (RPT token) which is used for authorization

For further details, please refer to API specification version 0.5 in Content Server.

# How to modify APIs:
* Modify APIs source code
* Add changes into CHANGE.md
* Add more test cases for automatic tests by modifying *lib/cfg_test_lib.py* and *test_script.rst*
* Run automatic tests

# How to change log level:
* Modify log level in *app/__init__.py"
> level=logging.INFO

# How to run automatic test for APIs:
* Install robot framework

* Modify the API URL in *lib/cfg_test_lib.py*

> API_URL = [URL of EMGUM API]

Example: API_URL = "https://api.emgora.eu/v1/emgum/api"

* Create a user with "manage-user" and "view-users" role in the Keycloak server

* Create two OIDC clients in the Keycloak server

* For the 1st created OIDC client, create a resource, a scope, a permission. Link the scope and permission to the created resource.

* Create an initial registration token in the Keycloak server

* Modify the variables values in *test_script.rst*

  ** ${initial_reg_token}: initial registration token
  
  ** ${client_id}: client_id of the 1st client
  
  ** ${client_secret}: client_secret of the 1st client
  
  ** ${another_client_id}: client_id of the 2nd client 
  
  ** ${another_client_secret}: client_secret of the 2nd client 
  
  ** ${resource_server}: client_secret of the 1st client
  
  ** ${resource}: resource of the 1st client
  
  ** ${scope}: scope of the 1st scope
  
  ** ${manager_user_name}: user name of the user with "manage-user" and "view-users" role
  
  ** ${manager_password}: password of the user with "manage-user" and "view-users" role

* Run the test script using robot framework

> robot test_script.rst