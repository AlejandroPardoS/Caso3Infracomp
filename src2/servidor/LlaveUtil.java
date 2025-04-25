package src2.servidor;

import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

public class LlaveUtil {

    public static PublicKey cargarLlavePublica(String ruta) throws Exception {
    try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(ruta))) {
        return (PublicKey) in.readObject();
        }
    }

    public static PrivateKey cargarLlavePrivada(String ruta) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(ruta))) {
            return (PrivateKey) in.readObject();
        }
    }
    
}
