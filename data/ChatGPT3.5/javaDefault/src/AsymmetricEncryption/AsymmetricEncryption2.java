import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class AsymmetricEncryption2 {

    private static final String ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    
    private static final String PRIVATE_KEY_FILE = "private.key";
    private static final String PUBLIC_KEY_FILE = "public.key";
    private static final String SYMMETRIC_KEY_FILE = "symmetric.key";

    public static void generateKeyPair() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        try (ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(PUBLIC_KEY_FILE));
             ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(PRIVATE_KEY_FILE))) {
            publicKeyOS.writeObject(keyPair.getPublic().getEncoded());
            privateKeyOS.writeObject(keyPair.getPrivate().getEncoded());
        }
    }

    public static void generateSymmetricKey() throws NoSuchAlgorithmException, IOException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        try (ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream(SYMMETRIC_KEY_FILE))) {
            outputStream.writeObject(secretKey.getEncoded());
        }
    }

    public static byte[] encryptSymmetricKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        
        try (ObjectInputStream publicKeyIS = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
             InputStream symmetricKeyIS = new FileInputStream(SYMMETRIC_KEY_FILE);
             ByteArrayOutputStream encryptedKeyBAOS = new ByteArrayOutputStream()) {
            byte[] publicKeyBytes = (byte[]) publicKeyIS.readObject();
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
            byte[] buffer = new byte[1024];
            int len;
            while ((len = symmetricKeyIS.read(buffer)) != -1) {
                byte[] encryptedData = cipher.doFinal(buffer, 0, len);
                encryptedKeyBAOS.write(encryptedData);
            }
            
            return encryptedKeyBAOS.toByteArray();
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static void decryptSymmetricKey(byte[] encryptedKeyData) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        
        try (ObjectInputStream privateKeyIS = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
             ByteArrayInputStream encryptedKeyBAIS = new ByteArrayInputStream(encryptedKeyData);
             OutputStream symmetricKeyOS = new FileOutputStream("decrypted" + SYMMETRIC_KEY_FILE)) {
            byte[] privateKeyBytes = (byte[]) privateKeyIS.readObject();
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            
            byte[] buffer = new byte[128];
            int len;
            while ((len = encryptedKeyBAIS.read(buffer)) != -1) {
                byte[] decryptedData = cipher.doFinal(buffer, 0, len);
                symmetricKeyOS.write(decryptedData);
            }
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        try {
            generateKeyPair();
            generateSymmetricKey();
            
            byte[] encryptedKeyData = encryptSymmetricKey();
            decryptSymmetricKey(encryptedKeyData);
            
            System.out.println("Symmetric key successfully encrypted and decrypted.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}