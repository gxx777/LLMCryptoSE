import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;

public class RSAEncryption4 {

    private static final String PUBLIC_KEY_FILE = "public.key";
    private static final String PRIVATE_KEY_FILE = "private.key";
    
    private static final String SYMMETRIC_KEY_FILE = "symmetric.key";

    public static void generateRSAKeys() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            
            try (ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(PUBLIC_KEY_FILE));
                 ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(PRIVATE_KEY_FILE))) {
                
                publicKeyOS.writeObject(keyPair.getPublic());
                privateKeyOS.writeObject(keyPair.getPrivate());
            }
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void encryptSymmetricKey() {
        try {
            Key publicKey = readKeyFromFile(PUBLIC_KEY_FILE, "public");
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] symmetricKey = "This is the symmetric key".getBytes();
            byte[] encryptedKey = cipher.doFinal(symmetricKey);
            
            try (FileOutputStream outputStream = new FileOutputStream(SYMMETRIC_KEY_FILE)) {
                outputStream.write(encryptedKey);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void decryptSymmetricKey() {
        try {
            Key privateKey = readKeyFromFile(PRIVATE_KEY_FILE, "private");
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);


            Path path = Paths.get(SYMMETRIC_KEY_FILE);
            byte[] encryptedKey = Files.readAllBytes(path);

//            try (FileInputStream inputStream = new FileInputStream(SYMMETRIC_KEY_FILE)) {
//                encryptedKey = inputStream.readAllBytes();
//            }
            
            byte[] symmetricKey = cipher.doFinal(encryptedKey);
            System.out.println("Decrypted symmetric key: " + new String(symmetricKey));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException e) {
            e.printStackTrace();
        }
    }

    private static Key readKeyFromFile(String fileName, String keyType) {
        try (ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(fileName))) {
            if (keyType.equals("public")) {
                return (PublicKey) inputStream.readObject();
            } else {
                return (PrivateKey) inputStream.readObject();
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        generateRSAKeys();
        encryptSymmetricKey();
        decryptSymmetricKey();
    }
}