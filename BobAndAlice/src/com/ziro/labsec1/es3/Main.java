package com.ziro.labsec1.es3;


import java.io.*;
import java.security.*;
import java.util.Arrays;
import java.util.Vector;

import com.polytech.Entity;
import com.polytech.security.*;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Main {

    public static void main(String [] args){
        if(args.length != 2){
            System.out.println("Usage error: <input file name> <output file name>");
            System.exit(0);
        }

        String input_file_name = args[0];
        String output_file_name = args[1];

        File f = new File(input_file_name);
        
        if(!f.exists()){
            System.out.println("Usage error: input file does not exist");
            System.exit(0);
        }

        FileInputStream fis = null;
        FileOutputStream fos = null;

        Provider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        Security.addProvider(prov);

        // create two new entity
        Entity Alice = new Entity();
        Entity Bob = new Entity();

        try{

            final String ALGORITHM = "DES";
            final String CIPHER_INSTANCE_NAME = "DES/ECB/NoPadding";

            /*
            Alice send her public key
            */
            PublicKey alicePublicKey = Alice.thePublicKey;

            /*
            Bob generate a session key and encrypts it with Alice's public key
            */
            SecretKey bob_session_key = KeyGenerator.getInstance(ALGORITHM).generateKey();
            byte[] encrypted_session_key = Bob.encrypt(bob_session_key.getEncoded(), alicePublicKey);

            /*
            Alice decrypt the DES key
            */
            byte[] DES_keys_encoded = Alice.decrypt(encrypted_session_key);
            SecretKey alice_session_key = new SecretKeySpec(DES_keys_encoded, 0, DES_keys_encoded.length, ALGORITHM);

            /*
            Alice use the DES session key to encrypt a message for BOB
             */
            fis = new FileInputStream(input_file_name);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            Cipher alice_cipher = Cipher.getInstance(CIPHER_INSTANCE_NAME, new BouncyCastleProvider());
            alice_cipher.init(Cipher.ENCRYPT_MODE, alice_session_key);

            byte[] orginal_message = IOUtils.toByteArray(fis);
            byte[] encrypted_message = alice_cipher.doFinal(orginal_message);

            /*
             Bob use his DES session key to decrypt the message from Alice
              */

            ByteArrayInputStream bis = new ByteArrayInputStream(encrypted_message);
            fos = new FileOutputStream(output_file_name);
            Cipher bob_cipher = Cipher.getInstance(CIPHER_INSTANCE_NAME, new BouncyCastleProvider());
            bob_cipher.init(Cipher.DECRYPT_MODE, bob_session_key);

            byte[] bob_clear_message = bob_cipher.doFinal(encrypted_message);
            IOUtils.write(bob_clear_message, fos);

            bos.close();
            bis.close();
        }catch(Exception e){
            e.printStackTrace();
            System.out.println("java Asymetric clearTextFile SignatureFile CipheredFile DecipheredFile");
        } finally {
            try {
                if(fis != null) fis.close();
                if(fos != null) fos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
