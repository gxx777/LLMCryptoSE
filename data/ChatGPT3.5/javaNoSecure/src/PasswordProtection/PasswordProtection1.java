import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;

public class PasswordProtection1 {
    
    private KeyStore keyStore;

    public PasswordProtection1() {
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void storePassword(String alias, char[] password) {
        try {
            keyStore.setEntry(alias, new SecretKeyEntry(new javax.crypto.spec.SecretKeySpec(new String(password).getBytes(), "AES")), new KeyStore.PasswordProtection(password));
            keyStore.store(null, password);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String retrievePassword(String alias, char[] password) {
        try {
            ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(password);
            SecretKeyEntry secretKeyEntry = (SecretKeyEntry) keyStore.getEntry(alias, protectionParameter);
            if (secretKeyEntry != null) {
                return new String(secretKeyEntry.getSecretKey().getEncoded());
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        return null;
    }
}