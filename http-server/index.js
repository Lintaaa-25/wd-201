
const http = require("http");
const fs = require("fs");
const minimist = require("minimist");

const args = minimist(process.argv.slice(2));
const PORT = args.port || 3000;

let homeContent = "";
let projectContent = "";
let registrationContent = "";

fs.readFile("home.html", (err, data) => {
  if (err) throw err;
  homeContent = data;
});

fs.readFile("project.html", (err, data) => {
  if (err) throw err;
  projectContent = data;
});

fs.readFile("registration.html", (err, data) => {
  if (err) throw err;
  registrationContent = data;
});

http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/html" });

  if (req.url === "/project") {
    res.write(projectContent);
  } else if (req.url === "/registration") {
    res.write(registrationContent);
  } else {
    res.write(homeContent);
  }

  res.end();
}).listen(PORT, () => {
  console.log(Server running on port ${PORT});
});  
