package com.polytech.security;



import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.util.*;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;


public class TripleDES {

	static public void main(String[] argv){

		Provider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(prov);

		try{

			if(argv.length>0){

				// Create a TripleDES object
				TripleDES the3DES = new TripleDES();
				if(argv[0].compareTo("-ECB")==0){
					// ECB mode
				  	// encrypt ECB mode
				  	Vector<SecretKey> Parameters=
					  	the3DES.encryptECB(
					  			new FileInputStream(new File(argv[1])),  	// clear text file
				   	  			new FileOutputStream(new File(argv[2])), 	// file encrypted
				   	  			"DES", 										// KeyGeneratorName
				   	  			"DES/ECB/NoPadding"); 						// CipherName
				  	// decrypt ECB mode
				  	the3DES.decryptECB(Parameters,				 			// the 3 DES keys
				  				new FileInputStream(new File(argv[2])),  	// the encrypted file
				   	  			new FileOutputStream(new File(argv[3])),	// the decrypted file
				   	 			"DES/ECB/NoPadding"); 		  				// CipherName
				}
				else if(argv[0].compareTo("-CBC")==0){
					// decryption
				  	// encrypt CBC mode
				  	Vector<SecretKey> Parameters =
					  	the3DES.encryptCBC(
					  			new FileInputStream(new File(argv[1])),  	// clear text file
				   	  			new FileOutputStream(new File(argv[2])), 	// file encrypted
				   	  			"DES", 										// KeyGeneratorName
					  			"DES/CBC/NoPadding"); 						// CipherName
				   	  			//"DES/CBC/PKCS5Padding"); 					// CipherName
				  	// decrypt CBC mode
				  	the3DES.decryptCBC(
				  				Parameters,				 					// the 3 DES keys
			  					new FileInputStream(new File(argv[2])),  	// the encrypted file
			  					new FileOutputStream(new File(argv[3])),	// the decrypted file
				  				"DES/CBC/NoPadding"); 						// CipherName
				  				//"DES/CBC/PKCS5Padding"); 		  			// CipherName
				}

			}

			else{
				System.out.println("java TripleDES -ECB clearTextFile EncryptedFile DecryptedFile");
				System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
			}
		}catch(Exception e){
			e.printStackTrace();
			System.out.println("java TripleDES -ECB clearTextFile EncryptedFile DecryptedFile");
			System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
		}
	}

	//Function to use reliably read bytestreams using FileInputStream
	private byte[] readFileAsByteStream(FileInputStream fis) {
		byte[] bytes = null;
		try {
			bytes = IOUtils.toByteArray(fis);
		} catch (Exception e) {
			System.out.println("Error reading file as bytestream");
		}
		return bytes;
	}


	/**
	 * 3DES ECB Encryption
	 */
	private Vector encryptECB(FileInputStream in,
							FileOutputStream out,
							String keyGeneratorInstanceName,
							String cipherInstanceName) {
		try{
			byte[] plainText = this.readFileAsByteStream(in);
			if (plainText.length % 8 != 0 && cipherInstanceName.contains("NoPadding")) {
				throw new Exception("Text Not block aligned. With no-padding, plaintext has to be a block multiple of 8 bytes");
			}
			// GENERATE 3 DES KEYS
			SecretKey secretKey;
			Vector<SecretKey> secretKeyList = new Vector();
			for (int i = 0; i < 3 ; i++) {
				secretKey = KeyGenerator.getInstance(keyGeneratorInstanceName).generateKey();
				secretKeyList.add(secretKey);
			}
			Cipher  cipher;
			Vector<Cipher> ciphersList = new Vector();
			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE FIRST GENERATED DES KEY
			cipher = Cipher.getInstance(cipherInstanceName, new BouncyCastleProvider());
			cipher.init(Cipher.ENCRYPT_MODE, secretKeyList.get(0));
        	ciphersList.add(cipher);
        	// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE SECOND GENERATED DES KEY
        	cipher = Cipher.getInstance(cipherInstanceName, new BouncyCastleProvider());
			cipher.init(Cipher.DECRYPT_MODE, secretKeyList.get(1));
        	ciphersList.add(cipher);
        	// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE THIRD GENERATED DES KEY

        	cipher = Cipher.getInstance(cipherInstanceName, new BouncyCastleProvider());
			cipher.init(Cipher.ENCRYPT_MODE, secretKeyList.get(2));
        	ciphersList.add(cipher);

			//Read file as a byte stream
			// GET THE MESSAGE TO BE ENCRYPTED FROM IN
			byte[] encodedText = plainText;
			// CIPHERING
				// CIPHER WITH THE FIRST KEY
				// DECIPHER WITH THE SECOND KEY
				// CIPHER WITH THE THIRD KEY
				// write encrypted file
			for (Cipher c : ciphersList) {
				encodedText = c.doFinal(encodedText);
			}
			// WRITE THE ENCRYPTED DATA IN OUT
			out.write(encodedText);
			// return the DES keys list generated
			return secretKeyList;
		} catch(Exception e){
			e.printStackTrace();
			return null;
		} finally {
			try {
				in.close();
				out.close();
			}
			catch(Exception e1){
				e1.printStackTrace();
			}
		}

	}

	/**
	 * 3DES ECB Decryption
	 */
	private void decryptECB(Vector <SecretKey> secretKeyList,
						FileInputStream in,
						FileOutputStream out,
						String cipherInstanceName){
		try{
			Vector<Cipher> ciphersList = new Vector();
			Cipher cipher;
			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE THIRD GENERATED DES KEY
			cipher = Cipher.getInstance(cipherInstanceName, new BouncyCastleProvider());
			cipher.init(Cipher.DECRYPT_MODE, secretKeyList.get(2));
        	ciphersList.add(cipher);
        	// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE SECOND GENERATED DES KEY
        	cipher = Cipher.getInstance(cipherInstanceName, new BouncyCastleProvider());
			cipher.init(Cipher.ENCRYPT_MODE, secretKeyList.get(1));
        	ciphersList.add(cipher);
        	// CREATE A DES CIPHER OBJECT FOR ENCRYPTION
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE FIRST GENERATED DES KEY
        	cipher = Cipher.getInstance(cipherInstanceName, new BouncyCastleProvider());
			cipher.init(Cipher.DECRYPT_MODE, secretKeyList.get(0));
        	ciphersList.add(cipher);

			// GET THE ENCRYPTED DATA FROM IN
			byte[] byteStream = this.readFileAsByteStream(in);
			byte[] decodedText = byteStream;
			// DECIPHERING
				// DECIPHER WITH THE THIRD KEY
				// 	CIPHER WITH THE SECOND KEY
				// 	DECIPHER WITH THE FIRST KEY
			for (Cipher c : ciphersList) {
				decodedText = c.doFinal(decodedText);
			}
			// WRITE THE DECRYPTED DATA IN OUT
			out.write(decodedText);
		}catch(Exception e){
			e.printStackTrace();
		} finally {
			try {
				in.close();
				out.close();
			}
			catch(Exception e1){
				e1.printStackTrace();
			}
		}
	}

	/**
	 * 3DES CBC Encryption
	 */
	private Vector encryptCBC(FileInputStream in,
							FileOutputStream out,
							String keyGeneratorInstanceName,
							String cipherInstanceName){
		try{
			// GET THE DATA TO BE ENCRYPTED FROM IN
			byte[] plainText = this.readFileAsByteStream(in);
			//Since we use nopadding, disallow any input that are not multiple of 8
			if (plainText.length % 8 != 0 && cipherInstanceName.contains("NoPadding")) {
				throw new Exception("Text Not block aligned. Try passing a padding");
			}
			// GENERATE 3 DES KEYS
			SecretKey secretKey;
			Vector<SecretKey> secretKeyList = new Vector();
			for (int i = 0; i < 3 ; i++) {
				secretKey = KeyGenerator.getInstance(keyGeneratorInstanceName).generateKey();
				secretKeyList.add(secretKey);
			}

			// GENERATE THE IV
			IvParameterSpec ivParams;
			SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
			byte[] iv = new byte[8];

			List<Byte> encodedTextContainingIVList = new ArrayList();
			Cipher cipher = null;
			Vector<Cipher> ciphersList = new Vector();

			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE FIRST GENERATED DES KEY
			cipher = Cipher.getInstance(cipherInstanceName, new BouncyCastleProvider());
			randomSecureRandom.nextBytes(iv);
			//I wish there was a better way in java to add all elements of one byte array to another dynamic sized byte[] array.
			encodedTextContainingIVList.addAll(Arrays.asList(ArrayUtils.toObject(iv)));
			ivParams = new IvParameterSpec(iv);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeyList.get(0), ivParams);
        	ciphersList.add(cipher);

        	// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE SECOND GENERATED DES KEY
        	cipher = Cipher.getInstance(cipherInstanceName, new BouncyCastleProvider());
			randomSecureRandom.nextBytes(iv);
			encodedTextContainingIVList.addAll(Arrays.asList(ArrayUtils.toObject(iv)));
			ivParams = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, secretKeyList.get(1), ivParams);
        	ciphersList.add(cipher);

        	// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE THIRD GENERATED DES KEY
        	cipher = Cipher.getInstance(cipherInstanceName, new BouncyCastleProvider());
			randomSecureRandom.nextBytes(iv);
			encodedTextContainingIVList.addAll(Arrays.asList(ArrayUtils.toObject(iv)));
			ivParams = new IvParameterSpec(iv);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeyList.get(2), ivParams);
        	ciphersList.add(cipher);

        	byte[] encodedText = plainText;

			// CIPHERING
				// CIPHER WITH THE FIRST KEY
				// DECIPHER WITH THE SECOND KEY
				// CIPHER WITH THE THIRD KEY
			for (Cipher c : ciphersList) {
				encodedText = c.doFinal(encodedText);
			}
			//encodedTextContainingIVList after next line will be [plaintextiv1, plaintextiv2, plaintextiv3, encypted_message]
			encodedTextContainingIVList.addAll(Arrays.asList(ArrayUtils.toObject(encodedText)));
			//Converting a List<Byte> to byte []. !!!!!!
			Byte[] encodedTextContainingIVListByteArray = encodedTextContainingIVList.toArray(new Byte[encodedTextContainingIVList.size()]);
			byte[] encodedTextContainingIV = ArrayUtils.toPrimitive(encodedTextContainingIVListByteArray);
			//Writing the encrypted data to file
			out.write(encodedTextContainingIV);
			// return the DES keys list generated
			return secretKeyList;

		} catch(Exception e){
			e.printStackTrace();
			return null;
		} finally {
			try {
				in.close();
				out.close();
			}
			catch(Exception e1){
				e1.printStackTrace();
			}
		}
	}

	/**
	 * 3DES ECB Decryption
	 */
	private void decryptCBC(Vector<SecretKey> secretKeyList,
						FileInputStream in,
						FileOutputStream out,
						String cipherInstanceName){
		try{
			//Get the encoded text from the file
			byte[] byteStream = this.readFileAsByteStream(in);
			//First 24 bits are 3 IVS of 8 byte each, and the rest of the array is the actual message
			//So extracting the actual message
			byte[] encodedText = Arrays.copyOfRange(byteStream, 24, byteStream.length);

			byte[] iv;
			IvParameterSpec ivParams;
			Vector<Cipher> ciphersList = new Vector();
			Cipher cipher;

			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE THIRD GENERATED DES KEY
				// With 3rd IV
			cipher = Cipher.getInstance(cipherInstanceName, new BouncyCastleProvider());
			//3rd IV
			iv = Arrays.copyOfRange(byteStream, 16, 24);
			ivParams = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, secretKeyList.get(2), ivParams);
        	ciphersList.add(cipher);

        	// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE 2ND GENERATED DES KEY
				// With 2ND IV

        	cipher = Cipher.getInstance(cipherInstanceName, new BouncyCastleProvider());
        	//2ND IV
        	iv = Arrays.copyOfRange(byteStream, 8, 16);
			ivParams = new IvParameterSpec(iv);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeyList.get(1), ivParams);
        	ciphersList.add(cipher);

        	// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE 1ST GENERATED DES KEY
				// With 1ST IV
        	cipher = Cipher.getInstance(cipherInstanceName, new BouncyCastleProvider());
        	//1ST IV
        	iv = Arrays.copyOfRange(byteStream, 0, 8);
			ivParams = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, secretKeyList.get(0), ivParams);
        	ciphersList.add(cipher);

			byte[] decodedText = encodedText;
			// DECIPHERING
				// DECIPHER WITH THE THIRD KEY
				// 	CIPHER WITH THE SECOND KEY
				// 	DECIPHER WITH THE FIRST KEY
			for (Cipher c : ciphersList) {
				decodedText = c.doFinal(decodedText);
			}
			// WRITE THE DECRYPTED DATA IN OUT
			out.write(decodedText);
		}catch(Exception e){
			e.printStackTrace();
		}finally {
			try {
				in.close();
				out.close();
			}
			catch(Exception e1){
				e1.printStackTrace();
			}
		}

	}
}
