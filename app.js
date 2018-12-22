
var express                 = require('express');
var app                     = express();
var request                 = require('request');
var bodyParser              = require('body-parser');
var crypto                  = require('crypto');
var utf8                    = require('utf8');
var https                   = require('https');

app.use(express.static("public"));
app.set("view engine", "ejs"); 
app.use(bodyParser.urlencoded({extended:  true}));

//Global varialbes
var base                    = 'https://';
var serviceBusUri           = '.servicebus.windows.net';


//Token input constructor
var eventHubRequest = function(eventHubName,primaryKey, policyName,tokenExpirationMin){
    this.eventHubName = eventHubName;
    this.uri = String(base + eventHubName + serviceBusUri);
    this.policyName = policyName;
    this.primaryKey = primaryKey;
    this.tokenExpirationMin = tokenExpirationMin;
};
//Main token generator method
function createSharedAccessToken(newRequest) { 
    if (!newRequest.uri || !newRequest.policyName || !newRequest.primaryKey) { 
            throw "Missing required parameter"; 
        } 
    var encoded = encodeURIComponent(newRequest.uri); 
    var now = new Date(); 
    var expiration = newRequest.tokenExpirationMin*60;
    var ttl = Math.round(now.getTime() / 1000) + expiration;
    var signature = encoded + '\n' + ttl; 
    var signatureUTF8 = utf8.encode(signature); 
    var hash = crypto.createHmac('sha256', newRequest.primaryKey).update(signatureUTF8).digest('base64'); 
    return 'SharedAccessSignature sr=' + encoded + '&sig=' +  
        encodeURIComponent(hash) + '&se=' + ttl + '&skn=' + newRequest.policyName; 
}

//Routes
app.get("/", function(req, res){
    res.render("index");
});
app.get("/token", function(req, res){
    res.render("token");
});

app.post("/token", function(req, res){
    var newRequest = new eventHubRequest(
        String(req.body.eventHubRequestEventHubName),
        String(req.body.eventHubRequestPrimaryKey),
        String(req.body.eventHubRequestPolicyName),
        Number(req.body.eventHubRequestTokenExpiration)
    );
    if (!newRequest.uri || !newRequest.policyName || !newRequest.primaryKey) { 
            res.status(400).send({"Error": "Required input missing"});
    }
    var SASToken = createSharedAccessToken(newRequest);
    res.render("token",{SASToken,newRequest});
});

app.post("/event", function(req, res){
    //Generate newRequest
     var newRequest = new eventHubRequest(
        String(req.body.eventHubRequestEventHubName),
        String(req.body.eventHubRequestPrimaryKey),
        String(req.body.eventHubRequestPolicyName),
        Number(req.body.eventHubRequestTokenExpiration)
    );
    if (!newRequest.uri || !newRequest.policyName || !newRequest.primaryKey) { 
            res.status(400).send({"Error": "Required input missing"});
    }
    var SASToken = req.body.SASToken;
    var requestBody = String(req.body.eventHubRequestBody);
    //Constructing options for server to server call
    var options = {
        host: newRequest.eventHubName + serviceBusUri,
        path: '/' + newRequest.eventHubName + '/messages',
        method: 'POST',
        headers: {
                'contentType': 'application/atom+xml;type=entry;charset=utf-8,application/json',
                'authorization': SASToken
        }
    };

    //HTTP Req
    var req = https.request(options,function(resObject){
        var responseString = "";
        resObject.on("data", function(data){
            responseString += data;
        });
        resObject.on("end", function(){
            console.log(responseString);
            if (resObject.statusCode != '201'){
                var requestStatus = JSON.stringify({
                    'StatusCode': resObject.statusCode,
                    'Message':JSON.stringify(responseString)
                });
                return res.render("response",{SASToken,newRequest,requestBody, requestStatus});
            } else {
                var requestStatus = JSON.stringify({
                    'StatusCode': resObject.statusCode,
                    'Message': 'Request sent successfully'
                });
                res.render("response",{SASToken,newRequest,requestBody, requestStatus});
            }
        });
    });
    //Send server to server request
    req.write(requestBody,utf8);
    req.on('error', (e) => {
          console.error(e.message);
    });
    req.end();
});

app.listen(process.env.PORT, process.env.IP, function(){
  console.log("Server started v3" + process.env.PORT);
});