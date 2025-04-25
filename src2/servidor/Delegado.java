package src2.servidor;

import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class Delegado implements Runnable {
    private Socket socket;

    public Delegado(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try (
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        ) {
            // Genera parámetros DH (p, g)
            DHParameterSpec dhParams = SeguridadUtil.generarParametrosDH();
            KeyPair parServidor = SeguridadUtil.generarDHKeyPair(dhParams);

            // Envia p, g y la clave pública del servidor al cliente
            out.writeObject(dhParams.getP());
            out.writeObject(dhParams.getG());
            out.writeObject(parServidor.getPublic().getEncoded());

            // Recibe la clave pública del cliente
            byte[] pubClienteEncoded = (byte[]) in.readObject();
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubClienteEncoded);
            PublicKey pubCliente = keyFactory.generatePublic(keySpec);

            // Calcula el secreto compartido y deriva llaves de sesión (AES + HMAC)
            byte[] secreto = SeguridadUtil.calcularSecretoCompartido(parServidor.getPrivate(), pubCliente);
            SecretKey[] llaves = SeguridadUtil.derivarLlaves(secreto);

            PrivateKey llavePrivada = LlaveUtil.cargarLlavePrivada("src2/keys/private.key");

            ServicioManager gestor = new ServicioManager();
            StringBuilder tabla = new StringBuilder("[");
            for (Servicio s : gestor.obtenerTodos()) {
                tabla.append(s.toString()).append(",");
            }
            tabla.deleteCharAt(tabla.length() - 1);
            tabla.append("]");

            // Firmar la tabla (autenticidad)
            byte[] datos = tabla.toString().getBytes();
            byte[] firma = SeguridadUtil.firmar(datos, llavePrivada);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(datos);
            baos.write(firma);
            byte[] datosFirmados = baos.toByteArray();

            // Generar IV y cifrar con AES
            byte[] ivBytes = new byte[16];
            new SecureRandom().nextBytes(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            byte[] cifrado = SeguridadUtil.cifrarAES(datosFirmados, llaves[0], iv);
            byte[] hmac = SeguridadUtil.calcularHMAC(cifrado, llaves[1]);

            System.out.println("Enviando IV...");
            out.writeObject(ivBytes);
            System.out.println("Enviando datos cifrados...");
            out.writeObject(cifrado);
            System.out.println("Enviando HMAC...");
            out.writeObject(hmac);
            System.out.println("Datos enviados exitosamente.");

            // Recibir consulta del cliente (ID cifrado + HMAC)
            byte[] consultaCifrada = (byte[]) in.readObject();
            byte[] hmacConsulta = (byte[]) in.readObject();

            // 2. Verifica integridad con HMAC
            byte[] hmacCalc = SeguridadUtil.calcularHMAC(consultaCifrada, llaves[1]);
            if (!MessageDigest.isEqual(hmacConsulta, hmacCalc)) {
                System.out.println("Error: HMAC inválido en la consulta.");
                return;
            }

            // Descifra con AES
            byte[] consultaDescifrada = SeguridadUtil.descifrarAES(consultaCifrada, llaves[0], iv);
            int idServicio = Integer.parseInt(new String(consultaDescifrada));

            Servicio serv = gestor.obtenerServicio(idServicio);
            String respuesta = (serv == null) ? "-1,-1" : serv.getIp() + ", " + serv.getPuerto();
            byte[] respuestaBytes = respuesta.getBytes();

            byte[] respuestaCifrada = SeguridadUtil.cifrarAES(respuestaBytes, llaves[0], iv);
            byte[] hmacResp = SeguridadUtil.calcularHMAC(respuestaCifrada, llaves[1]);

            out.writeObject(respuestaCifrada);
            out.writeObject(hmacResp);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}
