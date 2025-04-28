package src2.servidor;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ServidorIterativo {

    private static final int PUERTO = 2020;
    private static final int MAX_CLIENTES = 1;

    public static void main(String[] args) {
        ExecutorService pool = Executors.newFixedThreadPool(MAX_CLIENTES);

        try (ServerSocket serverSocket = new ServerSocket(PUERTO)) {
            System.out.println("Servidor principal escuchando en el puerto " + PUERTO);

            while (true) {
                Socket cliente = serverSocket.accept();
                System.out.println("Cliente conectado: " + cliente.getInetAddress());
                pool.execute(new DelegadoIterativo(cliente));  // Usamos DelegadoIterativo en vez de Delegado
            }

        } catch (IOException e) {
            System.err.println("Error en el servidor: " + e.getMessage());
        }
    }

}
