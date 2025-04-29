package src2.servidor;

import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import src2.cliente.ClienteIterativo;

public class DelegadoIterativo implements Runnable {
    private Socket socket;


    public DelegadoIterativo(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try (
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        ) {
            // Genera parámetros DH (p, g)
            long startTiempoTotal = 0;
            for (int i = 0; i < 1000; i++) {
                DHParameterSpec dhParams = SeguridadUtil.generarParametrosDH();
                KeyPair parServidor = SeguridadUtil.generarDHKeyPair(dhParams);

                // Envia p, g y la clave pública del servidor al cliente
                out.writeObject(dhParams.getP());
                out.writeObject(dhParams.getG());
                out.writeObject(parServidor.getPublic().getEncoded()); // esto es G^x

                PrivateKey llavePrivada = LlaveUtil.cargarLlavePrivada("src2/keys/private.key");

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(baos);
                oos.writeObject(dhParams.getG());
                oos.writeObject(dhParams.getP());
                oos.writeObject(parServidor.getPublic().getEncoded());
                oos.close();
                byte[] datos = baos.toByteArray(); // (G, P, G^x)

                long startFirma = System.nanoTime();
                byte[] firma = SeguridadUtil.firmar(datos, llavePrivada); // F(Kw-, (G,P,G^x))
                out.writeObject(firma); // F(Kw-, (G,P,G^x))
                long endFirma = System.nanoTime();
                System.out.println("Tiempo para firmar (ns): " + (endFirma - startFirma));

                byte[] gy = (byte[]) in.readObject(); // G^y del cliente
                KeyFactory keyFactory = KeyFactory.getInstance("DH");
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(gy);
                PublicKey pubCliente = keyFactory.generatePublic(keySpec);
                byte[] calculoSecretoDelegado = SeguridadUtil.calcularSecretoCompartido(parServidor.getPrivate(), pubCliente); //(G^x)^y

                SecretKey[] llaves = SeguridadUtil.derivarLlaves(calculoSecretoDelegado);
                
                byte[] ivBytes = (byte[]) in.readObject();
                IvParameterSpec iv = new IvParameterSpec(ivBytes);
            
                ServicioManager gestor = new ServicioManager();
                Map<Integer, String> nombresServicios = gestor.obtenerNombresServicios();

            
                StringBuilder tabla = new StringBuilder("[");
                for (Map.Entry<Integer, String> entry : nombresServicios.entrySet()) {
                    int id = entry.getKey();
                    String nombre = entry.getValue();
                    tabla.append("{\"id\":").append(id).append(",\"nombre\":\"").append(nombre).append("\"},");
                }
                tabla.deleteCharAt(tabla.length() - 1); // Eliminar la última coma
                tabla.append("]");
                long startCifradoSimetrico = System.nanoTime();
                byte[] datosServicios = tabla.toString().getBytes();
                byte[] datosServiciosCifrado = SeguridadUtil.cifrarAES(datosServicios, llaves[0], iv);
                long endCifradoSimetrico = System.nanoTime();
                startTiempoTotal += endCifradoSimetrico - startCifradoSimetrico;
                
                byte[] hmac = SeguridadUtil.calcularHMAC(datosServicios, llaves[1]);
                
                out.writeObject(datosServiciosCifrado); // Enviar datos cifrados
                out.writeObject(hmac); // Enviar HMAC

                byte[] servicioCliente = (byte[]) in.readObject(); // Recibir consulta del cliente
                byte[] hmacConsulta2 = (byte[]) in.readObject(); // HMAC de la consulta

                byte[] datosCalculados = SeguridadUtil.descifrarAES(servicioCliente, llaves[0], iv);
                long startVerificacion = System.nanoTime();
                byte[] hmacConsulta = SeguridadUtil.calcularHMAC(datosCalculados, llaves[1]);

                if (!MessageDigest.isEqual(hmacConsulta2, hmacConsulta)) {
                    System.out.println("Error: HMAC inválido en respuesta.");
                    return;
                }
                long endVerificacion = System.nanoTime();
                System.out.println("Tiempo para verificar consulta (ns): " + (endVerificacion - startVerificacion));

                String datosServicioDesaeado = new String(datosCalculados, StandardCharsets.UTF_8);
                String[] partes = datosServicioDesaeado.split("\\+");
                int id = Integer.parseInt(partes[0]);
                //String ipCliente = partes[1];

                // Obtener el servicio deseado
                String respuesta = "";
                if(gestor.existeServicio(id)){
                    respuesta = gestor.obtenerServicio(id).getIp() + ", " + gestor.obtenerServicio(id).getPuerto();
                } else {
                    respuesta = "-1,-1";
                }
                byte[] respuestaBytes = respuesta.getBytes();
                long startCifradoRespuestaSimetrico = System.nanoTime();
                byte[] respuestaCifrada = SeguridadUtil.cifrarAES(respuestaBytes, llaves[0], iv);
                long endCifradoRespuestaSimetrico = System.nanoTime();
                System.out.println("Tiempo para cifrar respuesta simetrica (ns): " + (endCifradoRespuestaSimetrico - startCifradoRespuestaSimetrico));
                startTiempoTotal += endCifradoRespuestaSimetrico - startCifradoRespuestaSimetrico;
    
                
                long startCifradoRespuestaAsimetrico = System.nanoTime();
                SeguridadUtil.cifrarRSA(respuestaBytes, LlaveUtil.cargarLlavePublica("src2/keys/public.key")); // Cifrado asimétrico
                long endCifradoRespuestaAsimetrico = System.nanoTime();
                System.out.println("Tiempo para cifrar respuesta asimetrico (ns): " + (endCifradoRespuestaAsimetrico - startCifradoRespuestaAsimetrico));
                
                byte[] hmacResp = SeguridadUtil.calcularHMAC(respuestaBytes, llaves[1]);
                out.writeObject(respuestaCifrada); // Enviar respuesta cifrada
                out.writeObject(hmacResp); // Enviar HMAC de la respuesta
            }
            System.out.println("Tiempo total de cifrado: " + startTiempoTotal);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
