package main

import (
	"time"
)


const (

	P_Login				= "login"
	P_Delete			= "delete"
	P_Signup			= "signup"
	P_Reset				= "reset"

	D_config_path		= "config.yaml"
	D_JWT_identity_key	= "email"
	D_User_ID			= "user_id"

	D_Reset_pass_time	= 5 * time.Minute
	D_Reset_check_time	= 5 * time.Minute
	D_2FA_time			= 5 * time.Minute

	D_2FA_DB			= "pending_2fa"
	D_USERS_DB			= "users"
)
