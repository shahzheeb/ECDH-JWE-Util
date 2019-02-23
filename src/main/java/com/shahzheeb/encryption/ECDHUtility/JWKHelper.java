package com.shahzheeb.encryption.ECDHUtility;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class JWKHelper {

    public static JWK generateJWK() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(Curve.P_256.toECParameterSpec());
        KeyPair keyPair = kpg.generateKeyPair();

        JWK jwk = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
                .privateKey((ECPrivateKey) keyPair.getPrivate())
                .build();

        return jwk;
    }

}
