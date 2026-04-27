import { sayHello } from "./utils/module.js";

console.log(`App started with PID: ${process.pid}`)

setInterval(sayHello,5000);


