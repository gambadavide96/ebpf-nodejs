const express = require('express');
const fs = require('fs'); 
const app = express();
const PORT = 3000;


// Aggiungiamo un middleware che scatta ad ogni richiesta
app.use((req, res, next) => {
  const logMessage = `[${new Date().toISOString()}] Request to: ${req.url}\n`;

  fs.appendFileSync(__dirname + '/access.log', logMessage);
  
  next(); // Passiamo il controllo alle rotte sottostanti
});

app.get('/', (req, res) => {
  res.send('Hello World!\n');
});

app.get('/about', (req, res) => {
  res.send('This is the about page!\n');
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
  console.log(`PID: ${process.pid}`);
});