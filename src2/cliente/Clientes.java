package src2.cliente;

public class Clientes {

    public static void main(String[] args) {
        int numClientes = 32; 

        for (int i = 0; i < numClientes; i++) {
            Thread clienteThread = new Thread(() -> {
                try {
                    Cliente.main(null); 
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            clienteThread.start(); // Inicia el hilo
        }
    }

}
