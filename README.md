# Nginx Takehome
Nginx Takehome assessment

My thought process/logic behind each solution is written below.


Q1. It asks how to configure Nginx so that any content ending with specific file extensions like css, jpg, jpeg, js, json, png, mp4, pdf returns a 404 error when accessed via curl. <br>
Solution. To solve this we will use `location` blocks in our Nginx configuration and create a regex to match the specific file extensions stated above. The regex `\.(css|jpg|jpeg|js|json|png|mp4|pdf)$` will match any request URI ending with the listed file extensions. Inside the location block, we will use `return 404;` to send a 404 response for requests matching these file extensions.
```js
location ~* \.(css|jpg|jpeg|js|json|png|mp4|pdf)$ {
  return 404;
}
```

Q2. This question asks us on how to log various fields in the Nginx access log, including time, Nginx version, remote address, request ID, status, and few other parameters. <br>
Solution. We can do this by defining a custom log format in the `http` block of our Nginx config using `log_format` module. We will include all the fields requested in the question like $time_local, $nginx_version, $remote_addr, $request_id, $status, etc., in our custom format. We will then set the `access_log` directive below in our config to specify the log file path and to use this custom format.
```js
log_format custom '$time_local $nginx_version $remote_addr $request_id $status $body_bytes_sent "$http_user_agent" $proxy_protocol_addr $server_name $upstream_addr $request_time $upstream_connect_time $upstream_header_time $upstream_response_time "$request" $upstream_status $ssl_session_reused "$http_x_forwarded_for"';
```
```js
access_log /var/log/nginx/access.log custom;
```

Q3. The third question is about adding HTTP security headers in Nginx, but only if they are not already set in the response from the upstream server. The question also lists default values for various headers like Strict-Transport-Security, X-Content-Type-Options, X-XSS-Protection etc. <br>
Solution. We will use another location block for this and utilize `add_header`. Here each `add_header` directive is wrapped in an `if block` that checks whether the respective header is already set in the upstream response. If the header is not present in the response (`$sent_http_*` variables are used for this purpose), then the `add_header` directive adds it. This ensures that headers are added conditionally, avoiding duplication if they are already set by the upstream server. The purpose of using the `always` parameter ensures headers are added regardless of response code.
```js
location / {
            # Proxy pass requests to an upstream server.
            proxy_pass http://your_upstream_server;

            # Add various security headers to the response conditionally.
            if ($sent_http_strict_transport_security = "") {
                add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
            }
            if ($sent_http_x_content_type_options = "") {
                add_header X-Content-Type-Options "nosniff" always;
            }
            if ($sent_http_x_xss_protection = "") {
                add_header X-XSS-Protection "1; mode=block" always;
            }
            if ($sent_http_x_frame_options = "") {
                add_header X-Frame-Options "DENY" always;
            }
            if ($sent_http_content_security_policy = "") {
                add_header Content-Security-Policy "frame-ancestors 'none'" always;
            }
            if ($sent_http_access_control_allow_credentials = "") {
                add_header Access-Control-Allow-Credentials "TRUE" always;
            }

            # Set headers to be passed to the upstream server.
            proxy_set_header X-Real-IP $remote_addr; # Pass the client's real IP.
            proxy_set_header Host $host; # Pass the request's host header.
        }
```
