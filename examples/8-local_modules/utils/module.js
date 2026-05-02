
import * as fs from 'fs';


const targetFile = 'password.txt';


function sayHello() {

    console.log("Hello!")

    fs.readFile(targetFile, 'utf8', function onRead(err, data) {
        if (err) {
            console.error(`[ERRORE] Impossibile leggere ${targetFile}: ${err.message}`);
            return;
        }
        console.log(`[SUCCESSO] Letto contenuto di ${targetFile}`);
        console.log(data);
    });
}

export{sayHello}