<master>
<h3>HTTP Authentication Driver</h3>
<p>
This simple package can be used by authorities that require the authentication
via HTTP-Request.
</p>
<p>Once installed you need to configure the 4 parameters:
<ul>
<li><code>http_auth_url</code> - The full URL to the server like http://myauthserver/auth.cgi
<li><code>http_auth_parameters</code> - A comma separated list of key-value pairs of
all required parameters except for username and password like "method=simple,encrypted=no"
<li><code>password</code> - The parameter name for the password parameter like "user"
<li><code>username</code> - The parameter name for the user id like "pw"
</ul>
</p>
<p>
Now create a new authority and select HTTP as the "Authentication" method.
</p>
<p>
Currently no password management is implemented.
</p>
