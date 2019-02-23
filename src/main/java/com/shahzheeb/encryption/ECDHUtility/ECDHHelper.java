package com.shahzheeb.encryption.ECDHUtility;

import javax.crypto.KeyAgreement;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ECDHHelper {

    public static byte[] generateSharedSecretKey(PrivateKey privateKey, PublicKey publicKey)
            throws NoSuchAlgorithmException, InvalidKeyException {

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);

        return keyAgreement.generateSecret();
    }
}
