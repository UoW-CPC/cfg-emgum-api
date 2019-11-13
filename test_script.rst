.. default-role:: code
.. code:: robotframework

	*** Settings *** 				
	Library     lib/cfg_test_lib.py
	Library           Collections

	*** Test Cases *** 
	Application with initial registration token could register itself as Keycloak client
		${client_id_res}    ${client_secret_res}    ${reg_token} =    Dynamically register client    ${initial_reg_token}   ${client_name}    ${redirect_uris}
		Set Global Variable     ${client_id_res}
		Set Global Variable     ${client_secret_res}
		Set Global Variable     ${reg_token}
		Status should be 	  ${http_code_ok}
	
	Client with registration token could update its information in Keycloak
		${new_reg_token} =    Update client       ${client_id_res}   ${reg_token}    ${new_redirect_uris}   ${new_client_name}
		Set Global Variable    ${new_reg_token}
		Status should be 	  ${http_code_ok}
	    Data should be     ${new_client_name}

	Client with registration token could retrieve its information in Keycloak
		Retrieve client     ${client_id_res}   ${new_reg_token}
		Status should be 	  ${http_code_ok}

	Client with invalid registration token cannot retrieve its information in Keycloak
		Retrieve client     ${client_id_res}   ${invalid_reg_token}
		Status should be 	  ${http_code_bad_request}	

	Client with invalid client_id token cannot retrieve its information in Keycloak
		Retrieve client     ${invalid_client_id}   ${new_reg_token}
		Status should be 	  ${http_code_bad_request}

	Client with expired registration token cannot retrieve its information in Keycloak
		Retrieve client    ${client_id_res}    ${reg_token}	
		Status should be 	  ${http_code_bad_request}
		
	Client with registration token could delete itself from Keycloak
		Delete client     ${client_id_res}   ${new_reg_token}
		Status should be 	  ${http_code_ok}

	Client could not retrieve its information after being deleted
		Retrieve client     ${client_id_res}   ${new_reg_token}
		Status should be 	  ${http_code_bad_request}

	User who is assigned 'manage-users' role can add a new user
	    ${manager_access_token}    ${manager_refresh_token} =    Retrieve tokens    ${client_id}     ${client_secret}     ${manager_user_name}    ${manager_password}
		Set Global Variable    ${manager_access_token}
		Add user    ${manager_access_token}    ${new_username}     ${new_password}    ${firstname}    ${lastname}    ${email}
		Status should be     ${http_code_created}

	User who is assigned 'manage-users' role can retrieve a user
		Retrieve user    ${manager_access_token}    ${new_username}
		Status should be     ${http_code_ok}
		Data should be    ${firstname}

	User who is assigned 'manage-users' role can update a user
		Update user    ${manager_access_token}    ${new_username}    ${firstname_update}    ${lastname_update}
		Status should be     ${http_code_ok}
		Retrieve user    ${manager_access_token}    ${new_username}
		Data should be    ${firstname_update}

	Client can retrieve access token and refresh token from user's username and password
		${access_token}    ${refresh_token} =    Retrieve tokens    ${client_id}     ${client_secret}     ${new_username}    ${new_password}
		Set Global Variable    ${access_token}
		Set Global Variable    ${refresh_token} 
		Status should be 	  ${http_code_ok}

	Client can introspect/ verify the access token
		Verify token    ${access_token}    ${client_id}     ${client_secret}
		Status should be 	  ${http_code_ok}

	Client can use the access token to retrieve the user information
		Retrieve userinfo    ${access_token}    ${client_id}     ${client_secret}
		Status should be 	  ${http_code_ok}

	Client can renew the access token
		${new_access_token}    ${new_refresh_token} =    Renew tokens     ${refresh_token}    ${client_id}     ${client_secret}
		Set Global Variable    ${new_access_token}
		Set Global Variable    ${new_refresh_token}
		Status should be 	  ${http_code_ok}

	Client can verify the new access token
		Verify token     ${new_access_token}    ${client_id}     ${client_secret}
		Status should be 	  ${http_code_ok}

	A client can exchange a received token to achieve its own token
		Exchange a token    ${new_access_token}    ${another_client_id}     ${another_client_secret}
		Status should be 	  ${http_code_ok}
		
	Client can retrieve a rpt token
		${rpt} =    Get rpt    ${new_access_token}   ${resource_server}   ${resource}    ${scope}
		Set Global Variable    ${rpt}
		Status should be 	  ${http_code_ok}
		
	Client can verify the rpt token
		Verify rpt    ${rpt}   ${client_id}   ${client_secret} 
		Status should be 	  ${http_code_ok}
	
	Client can send log out request to Keycloak
		Log out    ${new_refresh_token}    ${client_id}     ${client_secret}
		Status should be 	  ${http_code_ok}

	Client cannot verify the access token after log out
		Verify token     ${new_access_token}    ${client_id}     ${client_secret}
		Status should be 	  ${http_code_bad_request}

	User who is assigned 'manage-users' role can delete a user
		Delete user    ${manager_access_token}    ${new_username}
		Status should be    ${http_code_ok}
		Retrieve user    ${manager_access_token}    ${new_username}
		Status should be    ${http_code_ok}
		Data should be    ${not_found_user}

	*** Variables ***
	${initial_reg_token}    [Provide initial registration token]   
	${invalid_reg_token}           '123'
	${client_name}              test1A
	${new_client_name}          test1B
	@{redirect_uris}             localhost1    localhost2
	${http_code_not_found}       404
	${http_code_created}		 201
	${http_code_bad_request}	 400
	${http_code_ok}              200
	${shares}					 3
	${threshold}				 2
	${invalid_threshold}		 0   
	@{new_redirect_uris}         localhost3	   localhost4
	${client_id}              [Provide client id of an OIDC client]  
	${client_secret}          [Provide client secret of an OIDC client] 
	${another_client_id}     [Provide client id of another OIDC client] 
	${another_client_secret}    [Provide client secret of another OIDC client] 
	${new_username}                peter
	${firstname}               Pete
	${lastname}                Whit
	${new_password}                peter123
	${email}                   peter@mail.com
	${firstname_update}        'Peter'
	${lastname_update}        'Pan'
	${invalid_client_id}       'abc'
	${super_user_token}      agagaga
	${resource_server}    [Provide client id of an OIDC client]   
	${resource}    [Provide resource name of the resource server] 
	${scope}    [Provide scope name of the resource server] 
	${manager_user_name}    [Provide user name of a user with 'manage-user' and 'view-users' role]
	${manager_password}    [Provide password of a user with 'manage-user' and 'view-users' role]
	${not_found_user}    The user does not exist

	*** Keywords ***
	Dynamically register client
		[Arguments]    ${initial_reg_token}    ${client_name}     ${redirect_uris}
		${output} =     dynamic_register_a_client    ${initial_reg_token}    ${client_name}    ${redirect_uris}
		[return]    ${output}

	Delete client
		[Arguments]    ${client_id} 	${reg_token}
		delete_a_client    ${client_id} 	${reg_token}

	Retrieve client
		[Arguments]    ${client_id} 	${reg_token}
		retrieve_a_client    ${client_id} 	${reg_token}

	Update client
		[Arguments]    ${client_id} 	${reg_token}      ${new_redirect_uris}    ${new_client_name}
		${output} =     update_a_client    ${client_id} 	${reg_token}     ${new_redirect_uris}    ${new_client_name}
		[return]    ${output}

	Retrieve tokens
		[Arguments]    ${client_id}     ${client_secret}     ${user_name}    ${password}
		${output} =    retrieve_all_tokens    ${client_id}     ${client_secret}     ${user_name}    ${password}
		[return]    ${output}

	Renew tokens
		[Arguments]     ${token}    ${client_id}     ${client_secret}
		${output} =    renew_access_token    ${token}    ${client_id}     ${client_secret}
		[return]    ${output}
	
	Exchange a token
		[Arguments]    ${received_token}   ${client_id}   ${client_secret}
		exchange_token    ${received_token}   ${client_id}   ${client_secret}	
		
	Verify token
		[Arguments]     ${token}    ${client_id}     ${client_secret}
		introspect_access_token        ${token}    ${client_id}     ${client_secret}

	Log out
		[Arguments]     ${token}    ${client_id}     ${client_secret}
		delete_tokens    ${token}    ${client_id}     ${client_secret}

	Add user
		[Arguments]     ${super_user_token}    ${username}       ${password}    ${firstname}    ${lastname}    ${email}
		add_a_user     ${super_user_token}    ${username}       ${password}    ${firstname}    ${lastname}    ${email}

	Retrieve user
		[Arguments]    ${super_user_token}    ${username}
		retrieve_a_user    ${super_user_token}    ${username}

	Delete user
		[Arguments]    ${super_user_token}     ${username}
		delete_a_user   ${super_user_token}    ${username}

	Update user
		[Arguments]    ${super_user_token}    ${username}    ${firstname}    ${lastname}
		update_a_user    ${super_user_token}     ${username}    ${firstname}    ${lastname}
		
	Get rpt
		[Arguments]    ${access_token}   ${resource_server}   ${resource}    ${scope}
		${output} =    retrieve_rpt    ${access_token}   ${resource_server}   ${resource}    ${scope}
		[return]    ${output}	

	Verify rpt
		[Arguments]    ${rpt}   ${client_id}   ${client_secret}
		introspect_rpt    ${rpt}   ${client_id}   ${client_secret}