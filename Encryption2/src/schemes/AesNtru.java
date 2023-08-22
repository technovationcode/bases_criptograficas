package schemes;

import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;
import net.sf.ntru.encrypt.*;

public class AesNtru
{

    public static void main(String[] args) throws Exception
     {
         new AesNtru().ExecuteNTRUEncryptionDecryptionProcess();
     }

     private void ExecuteNTRUEncryptionDecryptionProcess() throws Exception
     {
         String message = "Welcome to Apress. Enjoy learning " + " practical cryptography and NTRU operations";

         // setup the parameters for NTRU and AES
         String ntru_aes_parameters = "AES/CBC/PKCS5Padding";
         int length_for_aes = 128;
         EncryptionParameters parameters_for_ntru = EncryptionParameters.APR2011_439_FAST;

         // setup an NTRU instance based on the encryption parameters
         // and generate the key pair using NTRU instance
         NtruEncrypt encryption_with_ntru = new NtruEncrypt(parameters_for_ntru);
         EncryptionKeyPair ntru_key_pair = encryption_with_ntru.generateKeyPair();


         System.out.println("Decrypted message = " + message.substring(0, 50) + "...");
         System.out.println("Length of plain message = " + message.length());
         System.out.println("Maximum length of NTRU = " + parameters_for_ntru.getMaxMessageLength());

         // compute the encryption of the message
         byte[] encryption_message = EncryptTheMessage(message.getBytes(),
                   ntru_key_pair.getPublic(),
                   ntru_aes_parameters,
                   length_for_aes,
                   parameters_for_ntru);

         System.out.println("Encrypted length = " + encryption_message.length +
                 " (NTRU=" + parameters_for_ntru.getOutputLength() + ", "
                 + "AES=" + (encryption_message.length - parameters_for_ntru.getOutputLength()) + ")");

         // compute the decryption of the message
         String decryption_message = new String(DecryptTheMessage(encryption_message,
                   ntru_key_pair,
                   ntru_aes_parameters,
                   length_for_aes,
                   parameters_for_ntru));

         System.out.println("The decryption of message is   = " + decryption_message.substring(0, 50) + "...");
         System.out.println("The length of the decrypted message is = " + decryption_message.length());
     }

     // encryption function will receive the following parameters:
     // - the public key
     // - the mode of AES
     // - the length of AES
     // - the encryption parameters for NTRU block
     private byte[] EncryptTheMessage(byte[] clearMessage,
               EncryptionPublicKey public_key,
               String modeOfAES,
               int lengthOfAES,
               EncryptionParameters ntru_parameters) throws Exception
     {
          // compute cryptographic AES key
         SecretKey cryptoKeyForAES = generateAesKey(lengthOfAES);

         // generate key specifications for encoding with AES - also it will for generating
         // the initialization vector (IV)
         SecretKeySpec key_specifications_aes = new SecretKeySpec(cryptoKeyForAES.getEncoded(), "AES");

         // providing encryption for message using AES
         Cipher algorithm = Cipher.getInstance(modeOfAES);
         algorithm.init(Cipher.ENCRYPT_MODE, key_specifications_aes);
         byte[] initialization_vector = algorithm.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
         byte[] encryption_with_aes = algorithm.doFinal(clearMessage);

         // encrypt AES key and IV with NTRU
         NtruEncrypt encryption_with_ntru = new NtruEncrypt(ntru_parameters);
         byte[] cryptoAESKey_Array = cryptoKeyForAES.getEncoded();
         byte[] initializationVector_and_cryptoKey = generate_byte_array(cryptoAESKey_Array, initialization_vector);
         byte[] encryptedResultWithNtru = encryption_with_ntru.encrypt(initializationVector_and_cryptoKey, public_key);

         // put everything in one byte array
         return generate_byte_array(encryptedResultWithNtru, encryption_with_aes);
     }


     // decryption function will receive the following parameters
     // - the encrypted message as an array of byte
     // - the decryption key pair
     // - the mode of AES
     // - the length of AES
     // - the encryption parameters related to NTRU block
     private byte[] DecryptTheMessage(byte[] encrypted_message,
               EncryptionKeyPair key_pair_for_encryption,
               String modeOfAES,
               int lengthOfAES,
              EncryptionParameters ntru_parameters) throws Exception
    {
         // set the encrypted ntru block based on the NTRU parameters
         NtruEncrypt encrypted_ntru_block = new NtruEncrypt(ntru_parameters);

        // obtain crypto key and initialization vector by decrypting the NTRU block
        byte[] encrypted_block_with_ntru = Arrays.copyOf(encrypted_message, ntru_parameters.getOutputLength());
        byte[] arrayOfKeyAndIV = encrypted_ntru_block.decrypt(encrypted_block_with_ntru, key_pair_for_encryption);
        byte[] arrayOfCryptoAESKey = Arrays.copyOf(arrayOfKeyAndIV, lengthOfAES/8);
        byte[] initializationVectorArray = Arrays.copyOfRange(arrayOfKeyAndIV, lengthOfAES/8, 2*lengthOfAES/8);

        // based on the AES crypto key and initialization vector, perform the decryption of the message
        byte[] encrypted_message_with_aes = Arrays.copyOfRange(encrypted_message,
                  encrypted_block_with_ntru.length,
                  encrypted_message.length);

        // specify the encryption mode of AES
        Cipher algorithm = Cipher.getInstance(modeOfAES);

        // configure the key specification related to the algorithm that we are using (e.g., AES)
        SecretKeySpec key_specification_aes = new SecretKeySpec(arrayOfCryptoAESKey, "AES");

        // set the specifications of the parameters for the initialization vector
        IvParameterSpec initialization_vector_specifications = new IvParameterSpec(initializationVectorArray);


        // initialize the algorithm for decryption by specifying the mode, the AES key and initialization vector
        algorithm.init(Cipher.DECRYPT_MODE, key_specification_aes, initialization_vector_specifications);

        // obtain the message in clear based on the encrypted message with AES
        byte[] messageInClear = algorithm.doFinal(encrypted_message_with_aes);

        // return the clear version of the message
        return messageInClear;
    }

    private SecretKey generateAesKey(int number_of_bits) throws Exception
    {
         // generate the key for AES
        KeyGenerator generatorForAESKey = KeyGenerator.getInstance("AES");

        // initialize the key based on the number of the bits
        generatorForAESKey.init(number_of_bits);

        // get and return the generated crypto key
        return generatorForAESKey.generateKey();
    }

    // based on two arrays (byteArray1 and byteArray2) generate a third one (byteArray3) by concatenate
    // the encrypted result with NTRU and encrypted result with AES
    private byte[] generate_byte_array(byte[] byteArray1, byte[] byteArray2)
    {
        // the final result of concatenation of byteArray1 (encrypted result with NTRU)
         // and byteArray2 (encrypted result with AES)
         byte[] byteArray3 = new byte[byteArray1.length + byteArray2.length];

         // perform the concatenation
        System.arraycopy(byteArray1, 0, byteArray3, 0, byteArray1.length);
        System.arraycopy(byteArray2, 0, byteArray3, byteArray1.length, byteArray2.length);

        // return the third-byte array containing the result of the concatenation
        return byteArray3;
          }
     }
