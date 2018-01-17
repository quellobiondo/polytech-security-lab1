package com.polytech;


import java.security.*;
import javax.crypto.*;

import java.io.*;
import java.util.Arrays;

public class Entity {

	private static final String ASYMMETRIC_ALGO = "RSA";
	private static final String SIGN_ALGO = "SHA1withRSA";
	private static final String MY_SIGN_DIGEST_ALGO = "SHA1";


	// keypair
	public PublicKey thePublicKey;
	private PrivateKey thePrivateKey;

	/**
	  * Entity Constructor
	  * Public / Private Key generation
	 **/
	public Entity(){
		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance (ASYMMETRIC_ALGO);
			kpg.initialize(1024, new SecureRandom());
			KeyPair kp = kpg.generateKeyPair();
			this.thePublicKey = kp.getPublic();
			this.thePrivateKey = kp.getPrivate();

		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
		}
	}

	/**
	  * Sign a message
	  * Parameters
	  * aMessage : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] sign(byte[] aMessage){
		
		try{
			Signature signature = Signature.getInstance(SIGN_ALGO);
			signature.initSign(this.thePrivateKey);
			signature.update(aMessage);
			return signature.sign();
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the message signature
	  * Result : signature true or false
	  **/
	public boolean checkSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
		try{
			Signature signature = Signature.getInstance(SIGN_ALGO);
			signature.initVerify(aPK);
			signature.update(aMessage);
			return signature.verify(aSignature);
		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}
	
	
	/**
	  * Sign a message
	  * Parameters
	  * aMessage : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] mySign(byte[] aMessage){
		
		try{
			Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGO);
			cipher.init(Cipher.ENCRYPT_MODE, thePrivateKey);
			MessageDigest md = MessageDigest.getInstance(MY_SIGN_DIGEST_ALGO);
			return cipher.doFinal(md.digest(aMessage));
			
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the message signature
	  * Result : signature true or false
	  **/
	public boolean myCheckSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
		try{
			Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGO);
			cipher.init(Cipher.DECRYPT_MODE, aPK);
			byte[] signed_digest = cipher.doFinal(aSignature);

			MessageDigest md = MessageDigest.getInstance(MY_SIGN_DIGEST_ALGO);
			byte[] message_digest = md.digest(aMessage);

			return Arrays.equals(signed_digest, message_digest);

		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}	
	
	
	/**
	  * Encrypt aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be encrypted
	  * aPK : a public key used for the message encryption
	  * Result : byte[] ciphered message
	  **/
	public byte[] encrypt(byte[] aMessage, PublicKey aPK){
		try{
			// get an instance of RSA Cipher
			// init the Cipher in ENCRYPT_MODE and aPK
			// use doFinal on the byte[] and return the ciphered byte[]
			Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGO);
			cipher.init(Cipher.ENCRYPT_MODE, aPK);

			return cipher.doFinal(aMessage);
			
		}catch(Exception e){
			System.out.println("Encryption error");
			e.printStackTrace();
			return null;
		}
	}

	/**
	  * Decrypt aMessage with the entity private key
	  * Parameters
	  * aMessage : byte[] to be encrypted
	  * Result : byte[] deciphered message
	  **/
	public byte[] decrypt(byte[] aMessage){
		try{
			// get an instance of RSA Cipher
			// init the Cipher in DECRYPT_MODE and aPK
			// use doFinal on the byte[] and return the deciphered byte[]
			Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGO);
			cipher.init(Cipher.DECRYPT_MODE, thePrivateKey);
			return cipher.doFinal(aMessage);
			
		}catch(Exception e){
			System.out.println("Encryption error");
			e.printStackTrace();
			return null;
		}

	}


}