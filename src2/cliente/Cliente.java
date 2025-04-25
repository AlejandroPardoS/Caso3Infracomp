package src2.cliente;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import src2.servidor.LlaveUtil;
import src2.servidor.SeguridadUtil;

public class Cliente {

    public static void main(String[] args) {
        try (
            Socket socket = new Socket("localhost", 12345);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        ) {
            // Recibe p, g y clave pública del servidor
            BigInteger p = (BigInteger) in.readObject();
            BigInteger g = (BigInteger) in.readObject();
            byte[] servidorPubEncoded = (byte[]) in.readObject();

            // Genera claves cliente y las envía
            DHParameterSpec dhParams = new DHParameterSpec(p, g);
            KeyPair parCliente = SeguridadUtil.generarDHKeyPair(dhParams);
            out.writeObject(parCliente.getPublic().getEncoded());

            // Reconstruye clave pública del servidor y deriva llaves de sesión
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(servidorPubEncoded);
            PublicKey pubServidor = keyFactory.generatePublic(keySpec);
            byte[] secreto = SeguridadUtil.calcularSecretoCompartido(parCliente.getPrivate(), pubServidor);
            SecretKey[] llaves = SeguridadUtil.derivarLlaves(secreto);

            System.out.println("Cliente: Intercambio de claves completado.");

            // Recibir tabla de servicios (cifrada, con HMAC)
            System.out.println("Esperando IV...");
            byte[] ivBytes = (byte[]) in.readObject();
            System.out.println("IV recibido.");
            byte[] cifrado = (byte[]) in.readObject();
            byte[] hmac = (byte[]) in.readObject();

            byte[] hmacLocal = SeguridadUtil.calcularHMAC(cifrado, llaves[1]);
            if (!MessageDigest.isEqual(hmac, hmacLocal)) {
                System.out.println("Error en la consulta: HMAC inválido");
                return;
            }

            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            byte[] datosFirmados = SeguridadUtil.descifrarAES(cifrado, llaves[0], iv);

            int firmaLen = 128;
            int datosLen = datosFirmados.length - firmaLen;
            byte[] datos = Arrays.copyOfRange(datosFirmados, 0, datosLen);
            byte[] firma = Arrays.copyOfRange(datosFirmados, datosLen, datosFirmados.length);

            PublicKey pub = LlaveUtil.cargarLlavePublica("src2/keys/public.key");
            if (!SeguridadUtil.verificarFirma(datos, firma, pub)) {
                System.out.println("Error en la consulta: Firma inválida");
                return;
            }

            System.out.println("Servicios disponibles:");
            System.out.println(new String(datos));

            // Enviar ID del servicio deseado
            int id = 1; // Hardcodeado para ejemplo
            byte[] idBytes = String.valueOf(id).getBytes();
            byte[] idCifrado = SeguridadUtil.cifrarAES(idBytes, llaves[0], iv);
            byte[] hmacConsulta = SeguridadUtil.calcularHMAC(idCifrado, llaves[1]);
            out.writeObject(idCifrado);
            out.writeObject(hmacConsulta);

            // Recibir respuesta del servidor (IP y puerto)
            byte[] respuestaCifrada = (byte[]) in.readObject();
            byte[] hmacRespuesta = (byte[]) in.readObject();

            byte[] hmacRespCalc = SeguridadUtil.calcularHMAC(respuestaCifrada, llaves[1]);
            if (!MessageDigest.isEqual(hmacRespuesta, hmacRespCalc)) {
                System.out.println("Error: HMAC inválido en respuesta.");
                return;
            }

            byte[] respuesta = SeguridadUtil.descifrarAES(respuestaCifrada, llaves[0], iv);
            System.out.println("Respuesta del servidor (IP, puerto): " + new String(respuesta));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
}
