import javax.crypto.Cipher;
import java.io.*;
import java.security.*;

public class RSAEncryption3 {
    
    private static final String PUBLIC_KEY_FILE = "public.key";
    private static final String PRIVATE_KEY_FILE = "private.key";
    
    public static void generateKeys() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            
            ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(PUBLIC_KEY_FILE));
            publicKeyOS.writeObject(keyPair.getPublic());
            publicKeyOS.close();
            
            ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(PRIVATE_KEY_FILE));
            privateKeyOS.writeObject(keyPair.getPrivate());
            privateKeyOS.close();
            
            System.out.println("RSA keys generated and saved successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void encryptSymmetricKey(String symKeyFile) {
        try {
            ObjectInputStream publicKeyIS = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
            PublicKey publicKey = (PublicKey) publicKeyIS.readObject();
            publicKeyIS.close();
            
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            
            byte[] symKeyBytes = new byte[16]; // Assume the symmetric key is 16 bytes long
            FileInputStream fis = new FileInputStream(symKeyFile);
            fis.read(symKeyBytes);
            fis.close();
            
            byte[] encryptedSymKey = cipher.doFinal(symKeyBytes);
            
            FileOutputStream fos = new FileOutputStream(symKeyFile + ".enc");
            fos.write(encryptedSymKey);
            fos.close();
            
            System.out.println("Symmetric key encrypted successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void decryptSymmetricKey(String encSymKeyFile) {
        try {
            ObjectInputStream privateKeyIS = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
            PrivateKey privateKey = (PrivateKey) privateKeyIS.readObject();
            privateKeyIS.close();
            
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            
            FileInputStream fis = new FileInputStream(encSymKeyFile);
            byte[] encryptedSymKey = new byte[256]; // Assume RSA encryption results in 256 bytes
            fis.read(encryptedSymKey);
            fis.close();
            
            byte[] decryptedSymKey = cipher.doFinal(encryptedSymKey);
            
            FileOutputStream fos = new FileOutputStream(encSymKeyFile.replace(".enc", ""));
            fos.write(decryptedSymKey);
            fos.close();
            
            System.out.println("Symmetric key decrypted successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void main(String[] args) {
        generateKeys();
        
        // Assume there is a symmetric key file named "symmetric.key"
        encryptSymmetricKey("symmetric.key");
        decryptSymmetricKey("symmetric.key.enc");
    }
}