package com.shahzheeb.encryption.ECDHUtility;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


@SpringBootApplication
public class ECDHUtilityApplication implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(ECDHUtilityApplication.class, args);
	}


	/**
	 * Organization A (sender) has to send some sensitive data to Organization B (receiver).
	 * Organization B has sent its public key to organization A - Which is the originator of the transaction.
	 * Organzation A will send its public key as part of JWE header to organization B
	 * @param args
	 * @throws Exception
	 */
	@Override
	public void run(String... args) throws Exception {

		System.out.println("Entering App: Generating Keys for Sender -------->");
		JWK senderKeys = JWKHelper.generateJWK();
		ECPublicKey senderPublicKey = ECKey.parse(senderKeys.toJSONString()).toECPublicKey();
		ECPrivateKey senderPrivateKey = ECKey.parse(senderKeys.toJSONString()).toECPrivateKey();

		System.out.println("Sender's Public Key : "+ DatatypeConverter.printHexBinary(senderPublicKey.getEncoded()));
		System.out.println("Sender's Private Key : "+ DatatypeConverter.printHexBinary(senderPrivateKey.getEncoded()));


		System.out.println("Entering App: Generating Keys for Receiver --------->");
		JWK receiverKeys = JWKHelper.generateJWK();
		ECPublicKey receiverPublicKey = ECKey.parse(receiverKeys.toJSONString()).toECPublicKey();
		ECPrivateKey receiverPrivateKey = ECKey.parse(receiverKeys.toJSONString()).toECPrivateKey();
		System.out.println("Receiver's Public Key : "+ DatatypeConverter.printHexBinary(receiverPublicKey.getEncoded()));
		System.out.println("Receiver's Private Key : "+ DatatypeConverter.printHexBinary(receiverPrivateKey.getEncoded()));


		System.out.println("<<<-------------GENERATING SECRETS ---------------->>>");
		byte[] senderSecretKey = ECDHHelper.generateSharedSecretKey(senderPrivateKey, receiverPublicKey);
		byte[] receiverSecretKey = ECDHHelper.generateSharedSecretKey(receiverPrivateKey, senderPublicKey);

		System.out.println("Sender's Secret Key  : "+ DatatypeConverter.printHexBinary(senderSecretKey));
		System.out.println("Receiver's Secret Key: "+ DatatypeConverter.printHexBinary(receiverSecretKey));


		System.out.println("<<<-----------------Create JWE at Sender's end ---------------->>>>");
		JWEObject jweObject = getJWEToken(senderPublicKey, senderSecretKey);
		String serializedJWEToken = jweObject.serialize(); // This will be send to the sender.
		System.out.println("Serialized JWEObject:"+jweObject.serialize());


		System.out.println("<<<-----------------Receiving and decoding JWE at Receiver's end ---------------->>>>");

		System.out.println("Security Provider : "+ Arrays.asList(Security.getProviders()));

		JWEObject jweObjectAtReceiver = JWEObject.parse(serializedJWEToken);

		ECDHDecrypter decrypter = new ECDHDecrypter(receiverPrivateKey);

		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		jweObjectAtReceiver.decrypt(decrypter);

		System.out.println(jweObjectAtReceiver.getPayload().toBase64URL().decodeToString());

	}


	private JWEObject getJWEToken(ECPublicKey publicKey, byte[] secret) throws JOSEException{

		/*JWTClaimsSet claims = new JWTClaimsSet.Builder()
				.claim("creditcardnumber", "3343989033228987")
				.claim("cvv", "222")
				.expirationTime(new Date(System.currentTimeMillis() + 86400 * 1000 * 2)) //expire after 2 days
				.build();*/

		//Payload payload = new Payload(claims.toJSONObject());
		Payload payload = new Payload("Shahzheeb Khan");
		System.out.println("Payload :"+payload);

		JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM);
		System.out.println("JWEHeader:"+jweHeader);

		SecretKey secretKey = new SecretKeySpec(secret, 0, secret.length, "AES");
		System.out.println("secretKey:"+ DatatypeConverter.printHexBinary(secretKey.getEncoded()));

		ECDHEncrypter encrypter = new ECDHEncrypter(publicKey, secretKey);

		JWEObject jweObject = new JWEObject(jweHeader, payload);

		jweObject.encrypt(encrypter);

		return jweObject;

	}
}
