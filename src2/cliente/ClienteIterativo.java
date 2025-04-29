package src2.cliente;

import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import src2.servidor.LlaveUtil;
import src2.servidor.SeguridadUtil;

public class ClienteIterativo {

    private static int numConsultas = 1000;

    public static void main(String[] args) {
        try (
            Socket socket = new Socket("localhost", 2020);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        ) {
            // Recibe p, g y clave pública del servidor
            for (int i = 0; i < numConsultas; i++) { 
                BigInteger p = (BigInteger) in.readObject();
                BigInteger g = (BigInteger) in.readObject();
                byte[] gx = (byte[]) in.readObject();

                PublicKey pub = LlaveUtil.cargarLlavePublica("src2/keys/public.key");

                byte[] firma = (byte[]) in.readObject();
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(baos);
                oos.writeObject(g);
                oos.writeObject(p);
                oos.writeObject(gx);
                oos.close();
                byte[] datos = baos.toByteArray(); // (G, P, G^x)

                if(!SeguridadUtil.verificarFirma(datos, firma, pub)){
                    System.out.println("Error en la consulta: HMAC inválido"); //bien
                    return;
                }
                
                // Genera claves cliente y las envía
                DHParameterSpec dhParams = new DHParameterSpec(p, g);
                KeyPair parCliente = SeguridadUtil.generarDHKeyPair(dhParams);
                KeyFactory keyFactory = KeyFactory.getInstance("DH");
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(gx);
                PublicKey pubServer = keyFactory.generatePublic(keySpec); // G^x
                byte[] calculoSecreto = SeguridadUtil.calcularSecretoCompartido(parCliente.getPrivate(), pubServer); //(G^x)^y
                out.writeObject(parCliente.getPublic().getEncoded()); // G^y se lo envio al servidor 
                
                SecretKey[] llaves = SeguridadUtil.derivarLlaves(calculoSecreto);
                byte[] ivBytes = new byte[16];
                new SecureRandom().nextBytes(ivBytes);
                IvParameterSpec iv = new IvParameterSpec(ivBytes);
                byte[] ivBytesEnviar = iv.getIV(); 
                out.writeObject(ivBytesEnviar); // IV para el cifrado

                byte[] respuestaCifrada = (byte[]) in.readObject();
                byte[] hmacRespuesta = (byte[]) in.readObject();

                byte[] datosCalculados = SeguridadUtil.descifrarAES(respuestaCifrada, llaves[0], iv);
                byte[] hmacConsulta = SeguridadUtil.calcularHMAC(datosCalculados, llaves[1]);

                if (!MessageDigest.isEqual(hmacRespuesta, hmacConsulta)) {
                    System.out.println("Error: HMAC inválido en respuesta.");
                    return;
                }

                String json = new String(datosCalculados);
                List<Integer> ids = new ArrayList<>();
                // Espera una estructura como: [{"id":1,"nombre":"EstadoVuelo"},...]
                Pattern pattern = Pattern.compile("\\{\"id\":(\\d+),\"nombre\":\"[^\"]+\"\\}");
                Matcher matcher = pattern.matcher(json);
                while (matcher.find()) {
                    int id = Integer.parseInt(matcher.group(1));
                    ids.add(id);
                }

            

                Random rand = new Random();
                int chance = rand.nextInt(100);

                int idSeleccionado;
                if (chance < 20) { 
                    idSeleccionado = 9999; // ID inválido
                } else {
                    idSeleccionado = ids.get(rand.nextInt(ids.size())); // ID válido
                }
                String idSeleccionadoString = String.valueOf(idSeleccionado);

                String servicioSeleccionado = idSeleccionadoString + '+' + socket.getInetAddress();
                //System.out.println("Servicio seleccionado: " + servicioSeleccionado);
                //pasa servicioSeleccionado a bytes
                byte[] idSeleccionadoBytes = servicioSeleccionado.getBytes();
                byte[] servicioDeseadoCifrado = SeguridadUtil.cifrarAES(idSeleccionadoBytes, llaves[0], iv);
                byte[] hmacConsulta2 = SeguridadUtil.calcularHMAC(idSeleccionadoBytes, llaves[1]);
                out.writeObject(servicioDeseadoCifrado);
                out.writeObject(hmacConsulta2);

                byte[] respuestaCifradaFinal = (byte[]) in.readObject();
                byte[] hmacRespuestaFinal = (byte[]) in.readObject();

                byte[] datosCalculadosFinal = SeguridadUtil.descifrarAES(respuestaCifradaFinal, llaves[0], iv);
                byte[] hmacConsultaFinal = SeguridadUtil.calcularHMAC(datosCalculadosFinal, llaves[1]);

                if (!MessageDigest.isEqual(hmacRespuestaFinal, hmacConsultaFinal)) {
                    //System.out.println("Error: HMAC inválido en respuesta. ESTE?");
                    return;
                } else {
                    String respuestaServer = new String(datosCalculadosFinal, StandardCharsets.UTF_8);
                    //System.out.println(respuestaServer);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public int getNumConsultas(){
        return this.numConsultas;
    }

}
