import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class PasswordProtection1 {

    private KeyStore keyStore;

    public PasswordProtection1() {
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void storePassword(String alias, char[] password) {
        try {
            Key key = new SecretKeySpec(password.toString().getBytes(), "AES");
            keyStore.setEntry(alias, new KeyStore.SecretKeyEntry((SecretKey) key),
                    new KeyStore.PasswordProtection(password));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean verifyPassword(String alias, char[] password) {
        try {
            Key key = keyStore.getKey(alias, password);
            return key != null;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static void main(String[] args) {
        PasswordProtection1 passwordProtection = new PasswordProtection1();
        char[] password = "secretPassword".toCharArray();
        passwordProtection.storePassword("user1", password);

        // Example of verifying password
        if (passwordProtection.verifyPassword("user1", password)) {
            System.out.println("Password verified successfully.");
        } else {
            System.out.println("Invalid password.");
        }
    }
}