package bloop;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import java.util.Map;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

// https://github.com/did-method-plc/did-method-plc/blob/main/README.md
record PlcOperationCreateUpdate(
    String type,
    List<String> rotationKeys,
    Map<String, String> verificationMethods,
    List<String> alsoKnownAs,
    Map<String, Object> services,
    String prev,
    String sig
) {
    public PlcOperationCreateUpdate {
        if (!type.equals("plc_operation")) {
            throw new IllegalArgumentException("The 'type' must have the fixed value 'plc_operation'.");
        }
    }

}

public class DidHelper {
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

    public static PublicKey getPublicKeyFromPem(String pemString) {
        byte[] pemContent;
        try {
            try(PemReader pemReader = new PemReader(new StringReader(pemString))) {
                pemContent = pemReader.readPemObject().getContent();
            }
        } catch(IOException e) {
            throw new RuntimeException(e);
        }

        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemContent);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            var privateKey = (ECPrivateKey) keyFactory.generatePrivate(keySpec);

            if (!privateKey.getAlgorithm().equalsIgnoreCase("EC")) {
                throw new IllegalArgumentException("Not an EC private key");
            }

            java.security.spec.ECParameterSpec ecParams = privateKey.getParams();
            java.math.BigInteger s = privateKey.getS();
            java.security.spec.ECPoint publicPoint = ecParams.getGenerator().multiply(s);
            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(publicPoint, ecParams);
            return keyFactory.generatePublic(publicKeySpec);

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static String generatePlcDid(Key rotationKey) {
        return null;
        /*
         * - did (string): the full DID identifier
         * - rotationKeys (array of strings): priority-ordered list of public keys in did:key encoding. must include least 1 key and at most 5 keys, with no duplication. control of the DID identifier rests in these keys. not included in DID document.
         * - verificationMethods (map with string keys and values): a set of service / public key mappings. the values are public keys did:key encoding; they get re-encoded in "multibase" form when rendered in DID document. the key strings should not include a # prefix; that will be added when rendering the DID document. used to generate verificationMethods of DID document. these keys do not have control over the DID document
         * - alsoKnownAs (array of strings): priority-ordered list of URIs which indicate other names or aliases associated with the DID identifier
         * - services (map with string keys; values are maps with type and endpoint string fields): a set of service / URL mappings. the key strings should not include a # prefix; that will be added when rendering the DID document.
         */

         // The DID itself is generated from a hash of the signed genesis operation

        // genesis = {
        //             "type": "plc_operation",
        //             "rotationKeys": [ crypto.encode_pubkey_as_did_key(rotation_key.public_key()) ],
        //             "verificationMethods": { "atproto": args["--repo_pubkey"] },
        //             "alsoKnownAs": [ "at://" + args["--handle"] ],
        //             "services": {
        //                 "atproto_pds": {
        //                     "type": "AtprotoPersonalDataServer",
        //                     "endpoint": args["--pds_host"]
        //                 }
        //             },
        //             "prev": None,
        //         }
        // }

        // var genesisOp = PlcOperationCreateUpdate("plc_operation",)
    }

}
