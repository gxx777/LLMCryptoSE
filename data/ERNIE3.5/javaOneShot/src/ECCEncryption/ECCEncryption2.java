//
//
//import org.bouncycastle.jce.ECNamedCurveTable;
//
//import javax.crypto.Cipher;
//import java.io.File;
//import java.io.FileInputStream;
//import java.io.FileOutputStream;
//import java.io.IOException;
//import java.nio.file.Files;
//import java.nio.file.Paths;
//import java.security.*;
//import java.security.spec.ECParameterSpec;
//import java.security.spec.ECPrivateKeySpec;
//import java.security.spec.ECPublicKeySpec;
//import java.util.Base64;
//
//public class ECCEncryption2 {
//
//    // ECC密钥对生成
//    private PrivateKey privateKey;
//    private PublicKey publicKey;
//
//    public ECCEncryption2() throws NoSuchAlgorithmException {
//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
//        keyGen.initialize(256); // 初始化密钥长度
//        KeyPair pair = keyGen.generateKeyPair();
//        this.privateKey = pair.getPrivate();
//        this.publicKey = pair.getPublic();
//    }
//
//    // 加密对称密钥
//    public String encryptSymmetricKey(byte[] symmetricKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("ECIES");
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        byte[] encrypted = cipher.doFinal(symmetricKey);
//        return Base64.getEncoder().encodeToString(encrypted);
//    }
//
//    // 解密对称密钥
//    public byte[] decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
//        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedSymmetricKey);
//        Cipher cipher = Cipher.getInstance("ECIES");
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//        return cipher.doFinal(encryptedBytes);
//    }
//
//    // 保存私钥到文件
//    public void savePrivateKey(String filePath) throws IOException {
//        FileOutputStream fos = new FileOutputStream(filePath);
//        fos.write(privateKey.getEncoded());
//        fos.close();
//    }
//
//    // 从文件加载私钥
//    public PrivateKey loadPrivateKey(String filePath) throws Exception {
//        byte[] encoded = Files.readAllBytes(Paths.get(filePath));
//        KeyFactory kf = KeyFactory.getInstance("EC");
//        return kf.generatePrivate(new ECPrivateKeySpec(encoded, new ECParameterSpec(
//                // 这里需要指定椭圆曲线参数，实际应用中可能需要从其他地方获取
//                // 例如使用椭圆曲线名称 "secp256r1"
//                ECNamedCurveTable.getParameterSpec("secp256r1")
//        )));
//    }
//
//    // 保存公钥到文件
//    public void savePublicKey(String filePath) throws IOException {
//        FileOutputStream fos = new FileOutputStream(filePath);
//        fos.write(publicKey.getEncoded());
//        fos.close();
//    }
//
//    // 从文件加载公钥
//    public PublicKey loadPublicKey(String filePath) throws Exception {
//        byte[] encoded = Files.readAllBytes(Paths.get(filePath));
//        KeyFactory kf = KeyFactory.getInstance("EC");
//        return kf.generatePublic(new ECPublicKeySpec(encoded, new ECParameterSpec(
//                // 同上，需要指定椭圆曲线参数
//                ECNamedCurveTable.getParameterSpec("secp256r1")
//        )));
//    }
//
//    // 测试方法
//    public static void main(String[] args) {
//        try {
//            ECCEncryption2 ecc = new ECCEncryption2();
//
//            // 假设有一个对称密钥
//            byte[] symmetricKey = "mySymmetricKey".getBytes();
//
//            // 加密对称密钥
//            String encryptedSymmetricKey = ecc.encryptSymmetricKey(symmetricKey);
//            System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);
//
//            // 解密对称密钥
//            byte[] decryptedSymmetricKey = ecc.decryptSymmetricKey(encryptedSymmetricKey);
//            System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));
//
//            // 保存并加载密钥
//            String privateKeyFilePath = "private.key";
//            String publicKeyFilePath = "public.key";
//            ecc.savePrivateKey(privateKeyFilePath);
//
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException(e);
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//    }
//}