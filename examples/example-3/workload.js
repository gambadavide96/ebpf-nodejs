// workload.js
const axios = require('axios');

/**
 * Simula una richiesta HTTP verso un servizio esterno.
 * Per intercettare la risoluzione DNS e i socket in uscita (syscall connect).
 */
async function fetchExternalData() {
    // Usiamo un'API pubblica di test
    const response = await axios.get('https://dummyjson.com/products/1');
    return response.data;
}

/**
 * Calcolo per generare carico puro sulla CPU 
 */
function calculateFibonacci(n) {
    if (n <= 1) return n;
    return calculateFibonacci(n - 1) + calculateFibonacci(n - 2);
}

module.exports = { fetchExternalData, calculateFibonacci };