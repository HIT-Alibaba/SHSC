var net = require('net');

var host = "10.211.55.11";
var port = 19910;
var client = new net.Socket();

client.hello = function() {
  var random1 = 1234123124;
  var msg = {"magic": random1, "type": "HELO"};
  this.write(JSON.stringify(msg));
};

client.connect(port, host, function() {
  console.log("Connected!");
  console.log("Sending Hello...");
  this.hello();
}); 
