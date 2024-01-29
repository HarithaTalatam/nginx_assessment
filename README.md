# Nginx Assessment

My thought process/logic behind each solution is written below.


Q1. It asks how to configure Nginx so that any content ending with specific file extensions like css, jpg, jpeg, js, json, png, mp4, pdf returns a 404 error when accessed via curl. <br>
Solution. Utilizing location blocks in the Nginx configuration, a regex (\.(css|jpg|jpeg|js|json|png|mp4|pdf)$) is employed to match URIs with the specified file extensions. Inside the location block, the directive return 404; is used to generate a 404 response for matching requests.
```js
location ~* \.(css|jpg|jpeg|js|json|png|mp4|pdf)$ {
  return 404;
}
```

Q2. This question asks us on how to log various fields in the Nginx access log, including time, Nginx version, remote address, request ID, status, and few other parameters. <br>
Solution. By defining a custom log format within the http block of the Nginx config using log_format, all requested fields, like $time_local, $nginx_version, $remote_addr, $request_id, $status, etc., are included. The access_log directive is then set in the config to specify the log file path and utilize the custom format.
```js
log_format custom '$time_local $nginx_version $remote_addr $request_id $status $body_bytes_sent "$http_user_agent" $proxy_protocol_addr $server_name $upstream_addr $request_time $upstream_connect_time $upstream_header_time $upstream_response_time "$request" $upstream_status $ssl_session_reused "$http_x_forwarded_for"';
```
```js
access_log /var/log/nginx/access.log custom;
```

Q3. The third question is about adding HTTP security headers in Nginx, but only if they are not already set in the response from the upstream server. The question also lists default values for various headers like Strict-Transport-Security, X-Content-Type-Options, X-XSS-Protection etc. <br>
Solution. A separate location block is used, employing add_header. Each add_header directive is enclosed in an if block checking whether the corresponding header is already set in the upstream response using $sent_http_* variables. If the header is not present, the add_header directive adds it. The use of the always parameter ensures headers are added regardless of the response code.
```js
location / {
            # Proxy passing the requests to an upstream server.
            proxy_pass http://your_upstream_server;

            # Adding various security headers to the response using If else conditional statements.
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
            

            # Set headers to be forwarded to the upstream server.
            proxy_set_header X-Real-IP $remote_addr; # Forward the client's real IP.
            proxy_set_header Host $host; # Forward the request's host header.
        }
    }
}
