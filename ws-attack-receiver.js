// Copyright (c) 2014, Arley Barros Leal da Silveira
// All rights reserved.
// 
// Note: I'm not by any means a pro node.js developer, this project was for prototyping, testing and fun :-)
//       Feel free to improve on this code.

// Declare necessary environment
var express     = require('express');
var https       = require('https');
var querystring = require('querystring');
var logentries  = require('node-logentries');
var app         = express();


// Personal metadata
var cf_tkn  = '<API Token from CloudFlare>';
var cf_email= '<Email registered at CloudFlare>'
var cf_zone = '<Domain registerd at Cloudflare>'
var le_tkn  = '<Logentries log facility token>'


// Global attack tolerance variables
var attack_tolerance_decay   = 60;    // Time in seconds which tolerance_counter is decremented by 1
var attack_tolerance_max     = 3000;  // Max value that tolerance_counter can reach, at +1 we are under attack!
var attack_tolerance_counter = 0;     // tolerance counter


var log = logentries.logger({
  token:le_tkn
});
app.configure(function () {
    app.use(express.urlencoded());
});


function cf_get_data (type, ip){
  // Build the post string 
  switch (type) {
    case 'block': // Threat control, ban IP!
      var data = querystring.stringify({
          'a'    : 'ban',         
          'tkn'  : cf_tkn,
          'email': cf_email,
          'key'  : ip
      });
      break;
    case 'help':  // I'm under attack!
      var data = querystring.stringify({
          'a'    : 'sec_lvl',         
          'tkn'  : cf_tkn,
          'email': cf_email,
          'z'    : cf_zone,
          'v'    : 'help'
      });
    case 'cool'  :  // I'm cool now!
      var data = querystring.stringify({
          'a'    : 'sec_lvl',         
          'tkn'  : cf_tkn,
          'email': cf_email,
          'z'    : cf_zone,
          'v'    : 'high'
      });      
      break;
    default:
      var data = null;
      break;
  }
  return data;
}
function cf_post_msg (type, ip) {
  // Get post data 
  var data = cf_get_data (type, ip);

  // Build the request
  var options = {
    hostname: 'www.cloudflare.com',
        port: 443,
        path: '/api_json.html',
      method: 'POST',
     headers: { 'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': data.length }
  };
  // Build request
  var req = https.request(options, function(res) {
    res.setEncoding('utf8');
    //
    res.on('data', function(d) {
      var jsonres = JSON.parse(d);
      if(jsonres.result!='success'){
        log.err('[RES]Cloudflare error: ', jsonres.msg )
      }
    });
    res.on('error', function(e){
        log.err("[RES]There was an error: ", e.message)
    });
  });
  req.write(data);
  req.end();

  req.on('error', function(e) {
    log.err('[REQ]There was an error:', e.message);
  });
}
function cf_tolerance_decay(){
  if (attack_tolerance_counter == 1) {
    log.info('Zeroing attack counter! Everything cool now!');
    cf_post_msg('cool', null);
  }
  if (attack_tolerance_counter>0) --attack_tolerance_counter;
};
/**************************************************************** 
 * Main code block                                              * 
 ****************************************************************/
getattack = function(request, response) {
  var attacklog = request.body.payload;
  var json      = JSON.parse(attacklog);
  var event     = json.event.m;

  // Strip IP
  attacker_ip = event.match('\CFCIP:{([^}]+)\}');
    
  // Log action
  log.crit("Blocking Attacker IP: ",attacker_ip[1]);
  
  // Post to Cloudflare.
  cf_post_msg('block', attacker_ip[1]);
  
  // Increment attack tolerance counter
  // Note: We still want to increment even if we fail to block on Cloudflare for any reason.
  //       That's important so we still try call the 'under attack' API
  ++attack_tolerance_counter;
  
  // Log Tolerance
  log.info("Tolerance counter:", attack_tolerance_counter, "|", attack_tolerance_max );
  
  // Check if we reach max tolerance counter and call Under Attack
  if (attack_tolerance_counter>attack_tolerance_max) {
     cf_post_msg('help', null);
     log.emerg("Site under Attack! Setting CloudFlare's countermeasures");
  }  
  response.send("bye bye");
}

app.post('/attack', getattack);   
app.listen(8080);

// Fire deacay timer
setInterval(cf_tolerance_decay, attack_tolerance_decay * 1000);
