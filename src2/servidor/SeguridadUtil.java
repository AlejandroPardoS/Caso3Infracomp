package src2.servidor;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

public class SeguridadUtil {

    // Genera parámetros DH (solo en servidor)
    public static DHParameterSpec generarParametrosDH() throws NoSuchAlgorithmException, InvalidParameterSpecException {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();
        return params.getParameterSpec(DHParameterSpec.class);
    }

    // Genera un par de llaves DH
    public static KeyPair generarDHKeyPair(DHParameterSpec paramSpec) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(paramSpec);
        return keyGen.generateKeyPair();
    }

    // Calcula el secreto compartido con DH
    public static byte[] calcularSecretoCompartido(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(privateKey);
        ka.doPhase(publicKey, true);
        return ka.generateSecret();
    }

    // Deriva dos llaves (AES y HMAC) desde SHA-512
    public static SecretKey[] derivarLlaves(byte[] secretoCompartido) throws NoSuchAlgorithmException {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(secretoCompartido);
        byte[] aesKeyBytes = Arrays.copyOfRange(digest, 0, 32);
        byte[] hmacKeyBytes = Arrays.copyOfRange(digest, 32, 64);

        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        SecretKey hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA256");

        return new SecretKey[]{aesKey, hmacKey};
    }

    public static byte[] cifrarAES(byte[] datos, SecretKey llave, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, llave, iv);
        return cipher.doFinal(datos);
    }

    public static byte[] descifrarAES(byte[] datos, SecretKey llave, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, llave, iv);
        return cipher.doFinal(datos);
    }

    // Cifrar con RSA (asimétrico)
    public static byte[] cifrarRSA(byte[] datos, PublicKey llavePublica) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, llavePublica);
        return cipher.doFinal(datos);
    }

    // Descifrar con RSA (asimétrico)
    public static byte[] descifrarRSA(byte[] datosCifrados, PrivateKey llavePrivada) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, llavePrivada);
        return cipher.doFinal(datosCifrados);
    }


    public static byte[] firmar(byte[] datos, PrivateKey llavePrivada) throws Exception {
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initSign(llavePrivada);
        firma.update(datos);
        return firma.sign();
    }

    public static boolean verificarFirma(byte[] datos, byte[] firmaBytes, PublicKey llavePublica) throws Exception {
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initVerify(llavePublica);
        firma.update(datos);
        return firma.verify(firmaBytes);
    }

    public static byte[] calcularHMAC(byte[] datos, SecretKey hmacKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        return mac.doFinal(datos);
    }
}

