// logger.js
const winston = require('winston');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        // Scrive su file per testare l'I/O (es. syscall write/openat)
        new winston.transports.File({ filename: 'serverLogs.log' }),
        new winston.transports.Console()
    ]
});

module.exports = logger;