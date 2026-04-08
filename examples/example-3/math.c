
// Questo attributo espone la funzione al mondo WebAssembly/JavaScript
__attribute__((export_name("fibonacci")))
int fibonacci(int n) {
    if (n <= 1) {
        return n;
    }

    return fibonacci(n - 1) + fibonacci(n - 2);
}

__attribute__((export_name("moltiplica")))
int moltiplica(int a, int b) {
    return a * b;
}