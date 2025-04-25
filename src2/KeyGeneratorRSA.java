package src2;

import java.security.*;
import java.io.*;

public class KeyGeneratorRSA {
    public static void main(String[] args) throws Exception {
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();

        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("src2/keys/public.key"))) {
            out.writeObject(pair.getPublic());
        }

        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("src2/keys/private.key"))) {
            out.writeObject(pair.getPrivate());
        }

        System.out.println("Llaves generadas correctamente.");
    }
}

