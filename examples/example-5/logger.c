// Dichiariamo una funzione esterna che verrà fornita da JavaScript
extern void write_on_stdout(int valore);


//Funzione di logica interna
int moltiplica(int a, int b) {
    return a * b;
}

//Funzione di logica interna
int mainLogic(int a, int b){
    int result = moltiplica(a,b);

    write_on_stdout(result);

    return result;
}

// Funzione Wasm che Node.js chiamerà
__attribute__((export_name("do_multiplication")))
void do_multiplication(int a, int b) {

    mainLogic(a,b);
}