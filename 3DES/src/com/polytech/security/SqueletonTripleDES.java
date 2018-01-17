package com.polytech.security;



import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import org.apache.commons.io.IOUtils;
import java.util.*;

public class SqueletonTripleDES{

	static public void main(String[] argv){

		Provider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(prov);

		try{

			if(argv.length>0){

				// Create a TripleDES object
				SqueletonTripleDES the3DES = new SqueletonTripleDES();
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
				  	Vector Parameters =
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


	/**
	 * 3DES ECB Encryption
	 */
	private Vector encryptECB(FileInputStream in,
							FileOutputStream out,
							String keyGeneratorInstanceName,
							String cipherInstanceName){
		try{

		/*	int content;
			while ((content = in.read()) != -1) {
				// convert to char and display it
				System.out.print((char) content);
			}*/
			// GENERATE 3 DES KEYS
			Vector<Cipher> ciphersList = new Vector();
			Vector<SecretKey> secretKeyList = new Vector();
			Cipher  cipher;
			SecretKey secretKey;
			for (int i = 0; i < 3 ; i++) {
				secretKey = KeyGenerator.getInstance(keyGeneratorInstanceName).generateKey();
				secretKeyList.add(secretKey);
				cipher = Cipher.getInstance(cipherInstanceName, new BouncyCastleProvider());
        		ciphersList.add(cipher);
			}

			ciphersList.get(0).init(Cipher.ENCRYPT_MODE, secretKeyList.get(0));
			ciphersList.get(1).init(Cipher.DECRYPT_MODE, secretKeyList.get(1));
			ciphersList.get(2).init(Cipher.ENCRYPT_MODE, secretKeyList.get(2));

			byte[] bytes = IOUtils.toByteArray(in);
			//System.out.println(Arrays.toString(bytes));

			for (Cipher c : ciphersList) {
				bytes = c.doFinal(bytes);
			}

			System.out.println(Arrays.toString(bytes));
			PrintWriter p;
			try {
				p = new PrintWriter(out, true);
    			p.println(new String(bytes));
			} catch (Exception e1) {
    			e1.printStackTrace();
			}
			//out.write(new String(bytes));


			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE FIRST GENERATED DES KEY

			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE SECOND GENERATED DES KEY

			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE THIRD GENERATED DES KEY

			// GET THE MESSAGE TO BE ENCRYPTED FROM IN

			// CIPHERING
				// CIPHER WITH THE FIRST KEY
				// DECIPHER WITH THE SECOND KEY
				// CIPHER WITH THE THIRD KEY
				// write encrypted file

			// WRITE THE ENCRYPTED DATA IN OUT

			// return the DES keys list generated
			in.close();
			out.close();
			return secretKeyList;

		}catch(Exception e){
			e.printStackTrace();
			return null;
		}

	}

	/**
	 * 3DES ECB Decryption
	 */
	private void decryptECB(Vector <SecretKey> keys,
						FileInputStream in,
						FileOutputStream out,
						String cipherInstanceName){
		try{
			Vector<Cipher> ciphersList = new Vector();
			Cipher cipher;
			for (int i=0; i<3; i++) {
				cipher = Cipher.getInstance(cipherInstanceName, new BouncyCastleProvider());

				ciphersList.add(cipher);

			}
			ciphersList.get(0).init(Cipher.DECRYPT_MODE, keys.get(2));
			ciphersList.get(1).init(Cipher.ENCRYPT_MODE, keys.get(1));
			ciphersList.get(2).init(Cipher.DECRYPT_MODE, keys.get(0));


			byte[] bytes = IOUtils.toByteArray(in);
			System.out.println(Arrays.toString(bytes));


			for (Cipher c : ciphersList) {
				System.out.print("DEBUG");
				bytes = c.doFinal(bytes);
			}

			//System.out.println(Arrays.toString(bytes));
			PrintWriter p;
			try {
				p = new PrintWriter(out, true);
    			p.println(new String(bytes));
			} catch (Exception e1) {
    			e1.printStackTrace();
			}

			//out.write(new String(bytes));

			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE THIRD GENERATED DES KEY

			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE SECOND GENERATED DES KEY

			// CREATE A DES CIPHER OBJECT WITH DES/ECB/PKCS5PADDING FOR ENCRYPTION
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE FIRST GENERATED DES KEY

			// GET THE ENCRYPTED DATA FROM IN

			// DECIPHERING
				// DECIPHER WITH THE THIRD KEY
				// 	CIPHER WITH THE SECOND KEY
				// 	DECIPHER WITH THE FIRST KEY

			// WRITE THE DECRYPTED DATA IN OUT
			in.close();
			out.close();

		}catch(Exception e){
			e.printStackTrace();
		}

	}

	/**
	 * 3DES ECB Encryption
	 */
	private Vector encryptCBC(FileInputStream in,
							FileOutputStream out,
							String KeyGeneratorInstanceName,
							String CipherInstanceName){
		try{

			// GENERATE 3 DES KEYS
			// GENERATE THE IV

			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE FIRST GENERATED DES KEY

			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE SECOND GENERATED DES KEY

			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE THIRD GENERATED DES KEY

			// GET THE DATA TO BE ENCRYPTED FROM IN

			// CIPHERING
				// CIPHER WITH THE FIRST KEY
				// DECIPHER WITH THE SECOND KEY
				// CIPHER WITH THE THIRD KEY

			// WRITE THE ENCRYPTED DATA IN OUT

			// return the DES keys list generated
			return null;

		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 3DES ECB Decryption
	 */
	private void decryptCBC(Vector Parameters,
						FileInputStream in,
						FileOutputStream out,
						String CipherInstanceName){
		try{

			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE THIRD GENERATED DES KEY

			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE SECOND GENERATED DES KEY

			// CREATE A DES CIPHER OBJECT WITH DES/ECB/PKCS5PADDING FOR ENCRYPTION
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE FIRST GENERATED DES KEY

			// GET ENCRYPTED DATA FROM IN

			// DECIPHERING
				// DECIPHER WITH THE THIRD KEY
				// 	CIPHER WITH THE SECOND KEY
				// 	DECIPHER WITH THE FIRST KEY

			// WRITE THE DECRYPTED DATA IN OUT

		}catch(Exception e){
			e.printStackTrace();
		}

	}


}
