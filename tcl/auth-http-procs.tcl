ad_library {
    Installation procs for authentication, account management and password management

    @author Nima Mazloumi (mazloumi@uni-mannheim.de)
    @creation-date 2005-07-04
    @cvs-id $Id$
}

namespace eval auth {}
namespace eval auth::http {}
namespace eval auth::http::authentication {}
namespace eval auth::http::password {}


ad_proc -private auth::http::after_install {} {} {
    set spec {
        contract_name "auth_authentication"
        owner "auth-http"
        name "HTTP"
        pretty_name "HTTP"
        aliases {
            Authenticate auth::http::authentication::Authenticate
            GetParameters auth::http::authentication::GetParameters
        }
    }

    set auth_impl_id [acs_sc::impl::new_from_spec -spec $spec]

    set spec {
        contract_name "auth_password"
        owner "auth-http"
        name "HTTP"
        pretty_name "HTTP"
        aliases {
            CanChangePassword auth::http::password::CanChangePassword
            ChangePassword auth::http::password::ChangePassword
            CanRetrievePassword auth::http::password::CanRetrievePassword
            RetrievePassword auth::http::password::RetrievePassword
            CanResetPassword auth::http::password::CanResetPassword
            ResetPassword auth::http::password::ResetPassword
            GetParameters auth::http::password::GetParameters
        }
    }

    set pwd_impl_id [acs_sc::impl::new_from_spec -spec $spec]
}

ad_proc -private auth::http::before_uninstall {} {} {
    
    acs_sc::impl::delete -contract_name "auth_authentication" -impl_name "HTTP"   
    acs_sc::impl::delete -contract_name "auth_password" -impl_name "HTTP"
    
}


#####
#
# HTTP Authentication Driver
#
#####


ad_proc -private auth::http::authentication::Authenticate {
    username
    password
    {parameters {}}
    {authority_id {}}
} {
    Implements the Authenticate operation of the auth_authentication 
    service contract for HTTP.
} {
    if { [auth::http::auth $username $password] } {
        set result(auth_status) ok
	ns_log Notice "auth-http: Authentication succeeded for $username"
    } else {
        set result(auth_status) auth_error
	ns_log Notice "auth-http: Authentication failed for $username"
    }

    set result(account_status) ok
    
    return [array get result]
}

ad_proc -private auth::http::authentication::GetParameters {} {
    Implements the GetParameters operation of the auth_authentication 
    service contract for HTTP.
} {
    return [list]
}


#####
#
# Password Driver
#
#####

ad_proc -private auth::http::password::CanChangePassword {
    {parameters ""}
} {
    Implements the CanChangePassword operation of the auth_password 
    service contract for HTTP.
} {
    return 0
}

ad_proc -private auth::http::password::CanRetrievePassword {
    {parameters ""}
} {
    Implements the CanRetrievePassword operation of the auth_password 
    service contract for HTTP.
} {
    return 0
}

ad_proc -private auth::http::password::CanResetPassword {
    {parameters ""}
} {
    Implements the CanResetPassword operation of the auth_password 
    service contract for HTTP.
} {
    return 0
}

ad_proc -private auth::http::password::ChangePassword {
    username
    new_password
    {old_password ""}
    {parameters {}}
    {authority_id {}}
} {
    Implements the ChangePassword operation of the auth_password 
    service contract for HTTP.
} {
}

ad_proc -private auth::http::password::RetrievePassword {
    username
    parameters
} {
    Implements the RetrievePassword operation of the auth_password 
    service contract for HTTP.
} {
}

ad_proc -private auth::http::password::ResetPassword {
    username
    parameters
    {authority_id {}}
} {
    Implements the ResetPassword operation of the auth_password 
    service contract for HTTP.
} {
}

ad_proc -private auth::http::password::GetParameters {} {
    Implements the GetParameters operation of the auth_password
    service contract for HTTP.
} {
    return [list]
}


ad_proc -private auth::http::auth {
    username
    password
} {
    Authenticates user by username and password
} {
    set server "[parameter::get_from_package_key -package_key auth-http -parameter http_auth_url -default ""]"
    set params "[parameter::get_from_package_key -package_key auth-http -parameter http_auth_parameters -default ""]"

    set parameters [split $params ","]
    lappend parameters "[parameter::get_from_package_key -package_key auth-http -parameter username -default "user"]=$username"
    lappend parameters "[parameter::get_from_package_key -package_key auth-http -parameter password -default "password"]=$password"

    set data [join $parameters "\n"]

    set hdrs [ns_set create]

    # headers necessary for a post and the form variables
    ns_set put $hdrs Accept "*/*"
    ns_set put $hdrs User-Agent "[ns_info name]-Tcl/[ns_info version]"
    ns_set put $hdrs "Content-type" "text/text"
    ns_set put $hdrs "Content-length" [string length $data]

    set http [ns_httpopen POST $server $hdrs 10 $data]

    set result ""
    set rfd [lindex $http 0]
    set wfd [lindex $http 1]
    set rpset [lindex $http 2]

    flush $wfd
    close $wfd

    set headers $rpset
    set response [ns_set name $headers]
    set status [lindex $response 1]

    set length [ns_set iget $headers content-length]
    if [string match "" $length] {set length -1}
    while 1 {
        set buf [_ns_http_read 10 $rfd $length]
        append result $buf
        if [string match "" $buf] break
        if {$length > 0} {
            incr length -[string length $buf]
            if {$length <= 0} break
        }
    }
    ns_set free $headers
    ns_set free $hdrs
    close $rfd

    set failure_token "[parameter::get_from_package_key -package_key auth-http -parameter failureToken -default "ERROR"]"
    set words [split $result "\n,\t, "]

    set found_p 0
    foreach word $words {
	
	if { [string match $failure_token $word] } {
	    set found_p 1
	    break
	}
    }
    
    #since we check against failure we return 0 if failed and 1 if failure_token was not found
    if { $found_p } {
	return 0
    } else {
	return 1
    }
}
