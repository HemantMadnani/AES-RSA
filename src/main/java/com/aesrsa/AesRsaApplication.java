package com.aesrsa;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AesRsaApplication {

	private static String secretKey = "HyperLinkSecret";
	private static String salt = "HyperLinkSalt";

	public static String decryptUsingRSAPublicKey(String encryptedText, PublicKey publicKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException {
		final Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText.getBytes())));
	}

	public static String descryptUsingAES256(String encryptedText, String aesDecrypted)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		final byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		final IvParameterSpec ivspec = new IvParameterSpec(iv);

		final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		final KeySpec spec = new PBEKeySpec(aesDecrypted.toCharArray(), salt.getBytes(), 65536, 256);
		final SecretKey tmp = factory.generateSecret(spec);
		final SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

		final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
		return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
	}

	public static String encryptUsingAES256(String plainText, String aesDecrypted) throws NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		final byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		final IvParameterSpec ivspec = new IvParameterSpec(iv);

		final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		final KeySpec spec = new PBEKeySpec(aesDecrypted.toCharArray(), salt.getBytes(), 65536, 256);
		final SecretKey tmp = factory.generateSecret(spec);
		final SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

		final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
		return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes("UTF-8")));
	}

	public static String encryptUsingRSAPrivateKey(String plainText, PrivateKey privateKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException {
		final Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
	}

	public static Map<String, Object> generateRSAKeys() throws NoSuchAlgorithmException {

		final Map<String, Object> map = new HashMap<>();

		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(4096);

		final KeyPair keyPair = keyPairGenerator.generateKeyPair();
		final PublicKey publicKey = keyPair.getPublic();
		final PrivateKey privateKey = keyPair.getPrivate();
		map.put("public", publicKey);
		map.put("private", privateKey);

		return map;
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException,
			UnsupportedEncodingException {
		SpringApplication.run(AesRsaApplication.class, args);

		final Map<String, Object> rsaKeys = generateRSAKeys();

		final PublicKey publicKey = (PublicKey) rsaKeys.get("public");
		final PrivateKey privateKey = (PrivateKey) rsaKeys.get("private");

		System.err.println("Public Key=" + publicKey.toString() + "\nPrivate Key=" + privateKey.toString());
		final String plainText = "Hello World";
		System.err.println("Text Before RSA Encryption===" + plainText);
		final String encryptedText = encryptUsingRSAPrivateKey(plainText, privateKey);
		System.err.println("Text AFTER RSA Encryption===" + encryptedText);
		System.err.println("Text AFTER RSA Decryption===" + decryptUsingRSAPublicKey(encryptedText, publicKey));
		System.err.println("Public Key in String format to store in file===="
				+ new String(Base64.getEncoder().encode(publicKey.getEncoded())));
//		final byte[] pub;
		// TODO get the string format of public key and decode in bytes and transform to
		// Original form using X509EncodedKeySpec
		final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		final X509EncodedKeySpec spec = new X509EncodedKeySpec(
				Base64.getDecoder().decode(new String(Base64.getEncoder().encode(publicKey.getEncoded()))));
		System.err.println("Getting Public key in normal format==="
				+ Base64.getDecoder().decode(new String(Base64.getEncoder().encode(publicKey.getEncoded()))));
		final PublicKey pubKe = keyFactory.generatePublic(spec);

		System.err.println("getting back Public Key =====" + pubKe);

		final String str = "\n".repeat(5);
		System.err.println(str);

		final String aesEncrypted = encryptUsingRSAPrivateKey(secretKey, privateKey);
		System.err.println("encrypting AES256 to store in DB===" + aesEncrypted);

		final String aesDecrypted = decryptUsingRSAPublicKey(aesEncrypted, publicKey);
		System.err.println("decrypting AES256 to perform encryption on plainText===" + aesDecrypted);

		final String simplePlainTextforAES = "Test Example";

		System.err.println("Simple text before AES Encryption==" + simplePlainTextforAES);

		final String encryptedAESText = encryptUsingAES256(simplePlainTextforAES, aesDecrypted);
		System.err.println("Encrypted AES Text===" + encryptedAESText);

		final String decryptedAES256Text = descryptUsingAES256(encryptedAESText, aesDecrypted);
		System.err.println("Decrypted AES Text====" + decryptedAES256Text);
	}

}
