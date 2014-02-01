node-haflare-webhook
==================

Node.js application webhook that parses logentries attack alarms logged by HAproxy and blocks on Cloudflare's threat control center.

####Features:
  - Tolerance control;
  - Cloudflare's Under Attack! automatic configuration under high load attacks;
  - Attack counter decay;
  - IP Attacker ban;

####Requirements:
  - Functional Logentries (www.logentries.com) account;
  - Most recent HAproxy snapshot with support to *capture.req.hdr* directive;
  - Your site configured to use Cloudflare's CDN and a working API Key;
  
  
##Configuration

####Node.js

Edit node-haflare-webhoook.js and add your personal information.
```javascript
var cf_tkn  = '< API Token from CloudFlare> ';
var cf_email= '< mail registered at CloudFlare >' 
var cf_zone = '< Domain registerd at Cloudflare >'
var le_tkn  = '< Logentries log facility token >'  
```
You will need only two packages: 
```json
  "dependencies": {
    "express": "3.x",
    "node-logentries": "~0.1.2"
  }
```
Write down your public IP and Port (default:8080), run your application :-)

####Logentries.com
You will need 2 log facilities, one as 'Node.js' type to receive events the application and another one, type 'Plain TCP, UDP', to receive logs from HAProxy;
- Create a new log for Node.js, follow steps and write down the log token to use it on the node-haflare-webhoook.js;
- Create a manual configuration log of type 'Plain TCP, UDP'. As soon as the log is created you will have a few minutes to configure HAProxy to send log events do Logentries can lock the port to you. Write down the port.
- On the HAproxy log created, set up a new Tag/Alarm with the following options:

> - Name: Bad Request
> - Pattern: NOSRV
> - Label: Fatal (or create a new one named Bad Request)
> - Log to apply: Select the HAproxy Log
> - Trigger: Once
> - Report: 100x / Hour
> - Check Webhook: http://YOUR_SERVER_IP:PORT/attack

####HAproxy
Point HAproxy to logentries.com facility, use the <port> given when you created the HAproxy log.
```
global 
    log 54.247.179.233:<port> local0 info
```

You will need a custom log format, ex:
```
log-format [%f|%b|%s]\ %ci:%cp\ %r\ %ST\ %B\ %ms\ %[capture.req.hdr(0)]\ CFCIP:{%[capture.req.hdr(1)]}
```
Only required field is **CFCIP:{%[capture.req.hdr(1)]}**. Check documentation and set up the log as you wish.

Setup the the frontend of your site with the following options:
```
frontend my-http-in
    capture request header User-Agent       len 200 # optional
    capture request header CF-Connecting-IP len 50
    
    # Optionally (you better), block all traffic not comming from Cloudflare's servers: 
    acl cloudflare_ranges src -f /opt/cloudflare/ips-v4
    # To get the ips-v4 file, crontab -e this job: 
    #      * 0 * * * wget -qO /opt/cloudflare/ips-v4 https://www.cloudflare.com/ips-v4
    
    # Block all request not coming from cloudflare or Local ISP
    http-request deny if !cloudflare_ranges 
    
    # Misbehaving Protection based on CF-Connecting-IP from Cloudflare
    # This does not protect againsts attacks bellow layer 7, but cloudflare will block it all!
    stick-table type ip size 100k expire 30s store conn_rate(3s)
    stick-table type ip size 1m   expire 10s store gpc0,http_req_rate(10s)
    stick-table type ip size 100k expire 30s store conn_cur
    
    tcp-request inspect-delay 10s
    tcp-request content track-sc0 hdr_ip(CF-Connecting-IP,-1) if HTTP

    http-request deny if { src_get_gpc0(http-in) gt 2 }
    http-request deny if { sc0_conn_cur  ge 10 }
    http-request deny if { sc0_conn_rate ge 10 }
    
    use_backend my_pool ... etc etc etc
    
````
#### Test IT !!!!
Use http://loadimpact.com/ free test, if everything is working ok you will see logentries receiveing the regular requests on you haproxy log and the attack being blocked on the node.js log.

Notes:

- The default tolerance is set to 3000, tune as you wish but never above the file descriptors your system can handle :-)
- Decay is set to 1m, so the attacker counter will decrement by 1 each minute. If you got your site on Under Attack! sec lvl it will only cooldown after the counter is zeroized. Tune as you wish.
