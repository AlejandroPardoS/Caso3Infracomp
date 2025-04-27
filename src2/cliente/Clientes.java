package src2.cliente;

public class Clientes {

    public static void main(String[] args) {
        int numeroClientes = 32; // Cambias a 4, 16, 32, 64 dependiendo del escenario

        for (int i = 0; i < numeroClientes; i++) {
            Thread clienteThread = new Thread(() -> {
                try {
                    Cliente.main(null); // Ejecuta el Cliente.java que ya tienes
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            clienteThread.start(); // ¡Inicia el hilo!
        }
    }

}
