package bloop;

import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class DIDHelper {
    public static KeyPair generateKeyPair(String curveName) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
            keyPairGenerator.initialize(ecSpec, new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }
    public static String convertKeyToPem(Key key, String keyType) {
        var sw = new StringWriter();
        try {
            try(var pemWriter = new PemWriter(sw)) {
                var pemObject = new PemObject(keyType, key.getEncoded());
                pemWriter.writeObject(pemObject);
            }
        } catch(IOException e) {
            throw new RuntimeException(e);
        }
        return sw.toString();
    }
    
}
