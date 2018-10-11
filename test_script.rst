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

	Client can retrieve access token and refresh token from user's username and password
		${access_token}    ${refresh_token} =    Retrieve tokens    ${client_id}     ${client_secret}     ${user_name}    ${password}
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

	
	Client can send log out request to Keycloak
		Log out    ${new_refresh_token}    ${client_id}     ${client_secret}
		Status should be 	  ${http_code_ok}

	Client cannot verify the access token after log out
		Verify token     ${new_access_token}    ${client_id}     ${client_secret}
		Status should be 	  ${http_code_bad_request}

	Super user can add a new user
		Add user    ${new_username}       ${new_password}    ${firstname}    ${lastname}    ${email}
		Status should be     ${http_code_created}

	Super user can retrieve a user
		Retrieve user    ${new_username}
		Status should be     ${http_code_ok}
		Data should be    ${firstname}

	Super user can update a user
		Update user    ${new_username}    ${firstname_update}    ${lastname_update}
		Status should be     ${http_code_ok}
		Retrieve user    ${new_username}
		Data should be    ${firstname_update}

	Super user can delete a user
		Delete user    ${new_username}
		Status should be    ${http_code_ok}
		Retrieve user    ${new_username}
		Status should be    ${http_code_bad_request}

	*** Variables ***
	${initial_reg_token}            eyJhbGciOiJSUzI1NiIsImtpZCIgOiAiR0RhdkZ5V1l5QXdrVkRQaVhRVWZxbHU2SVY4cTJXV2VTUUNqa2ltVktUSSJ9.eyJqdGkiOiIwMTA3Yzg0Mi04YjJjLTRhMjUtODFiMC04MDM1YTY0M2Q1ODAiLCJleHAiOjE1NDAwMzYwOTYsIm5iZiI6MCwiaWF0IjoxNTM5MTcyMDk2LCJpc3MiOiJodHRwOi8vMTg1LjEyLjUuOTg6ODA4MC9hdXRoL3JlYWxtcy9yZWFsbTAxIiwiYXVkIjoiaHR0cDovLzE4NS4xMi41Ljk4OjgwODAvYXV0aC9yZWFsbXMvcmVhbG0wMSIsInR5cCI6IkluaXRpYWxBY2Nlc3NUb2tlbiJ9.GeAKeu1UzptskFtZI00jw3U4lvkxHulj6Z6QXIsC4wtamRMyDiSz6Umv3cvuxyUBHV0u18pGRyTwnxB7hBhaibKFfJ-mSxEOo3Ox5Gl30fbWeU4mV_KDdpbro-X4av-mDYXCLmHANl-bZbGleKpEtgU8GDDanDn2B9pjMv1iNm54zSAGboU1vtrO7sn_-RHx-IerEXDdkMjXJLKUw_AsKPeUP1CVRNPSqoVN6zbBo3srt2ZEr0tcGHPUTlwuAQ29vlRw6QXTqtbmbTL0LlcajrnqRsZQHyBKQKv3vepReTY69_RvcSErb9t19Sbw_EfMiDpG3ISKlBk3zubyVKReRA
	${invalid_reg_token}           '123'
	${client_name}              app11a
	${new_client_name}          app11b
	@{redirect_uris}             localhost1    localhost2
	${http_code_not_found}       404
	${http_code_created}		 201
	${http_code_bad_request}	 400
	${http_code_ok}              200
	${shares}					 3
	${threshold}				 2
	${invalid_threshold}		 0   
	@{new_redirect_uris}         localhost3	   localhost4
	${user_name}                 user01
	${password}                  123
	${client_id}              app01
	${client_secret}          e532ea62-2743-4cea-89b3-ffc58664f739
	${new_username}                user11
	${firstname}               user11fn
	${lastname}                user11ln
	${new_password}                user123
	${email}                   user11@mail.com
	${firstname_update}        user11fn_update
	${lastname_update}         user11ln_update
	${invalid_client_id}       'abc'

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

	Verify token
		[Arguments]     ${token}    ${client_id}     ${client_secret}
		introspect_access_token        ${token}    ${client_id}     ${client_secret}

	Log out
		[Arguments]     ${token}    ${client_id}     ${client_secret}
		delete_tokens    ${token}    ${client_id}     ${client_secret}

	Add user
		[Arguments]     ${username}       ${password}    ${firstname}    ${lastname}    ${email}
		add_a_user    ${username}       ${password}    ${firstname}    ${lastname}    ${email}

	Retrieve user
		[Arguments]    ${username}
		retrieve_a_user    ${username}

	Delete user
		[Arguments]    ${username}
		delete_a_user    ${username}

	Update user
		[Arguments]    ${username}    ${firstname}    ${lastname}
		update_a_user    ${username}    ${firstname}    ${lastname}