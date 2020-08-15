/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package controller;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

//java imports
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import model.ProjectMainModel;
import view.EncryptMessageWindow;
/**
 *
 * @author Korisnik
 */
public class EncryptionController implements ActionListener {
    
    
    @Override
    public void actionPerformed(ActionEvent e) 
    {
        File[] files;
        JFileChooser fileChooser = new JFileChooser("Choose files to be encrypted.");
        fileChooser.setMultiSelectionEnabled(true);
	int retVal = fileChooser.showOpenDialog(null);
        if(retVal == JFileChooser.APPROVE_OPTION)
        {
            files = fileChooser.getSelectedFiles();
            for(File file : files)
                System.out.println(file.getName());
            
            EncryptMessageWindow encryptWindow = new EncryptMessageWindow();
            encryptWindow.setVisible(true);
            encryptWindow.addWindowListener(new WindowAdapter() 
            {
                @Override
                public void windowClosing(WindowEvent windowEvent)
                {
                    String publicKeyUserId = (encryptWindow.getCbPublicKeys().getSelectedItem().toString().split("\\(")[0]).strip();
                    System.out.println("User id: " + publicKeyUserId);
                    PGPPublicKey publicKey = null;
                    Iterator publicKeyRingIter =  ProjectMainModel.publicKeyRingCollection.getKeyRings();
                    while (publicKeyRingIter.hasNext()) 
                    {
                        PGPPublicKeyRing keyRing = (PGPPublicKeyRing) publicKeyRingIter.next();
                        if(keyRing.getPublicKey().getUserIDs().next().toString().equals(publicKeyUserId))                        
                              publicKey = keyRing.getPublicKey();
                    }        
                    if(publicKey != null)
                        System.out.println("Public key: " + Long.toHexString(publicKey.getKeyID()));
                        
                    String secretKeyUserId = (encryptWindow.getCbSecretKeys().getSelectedItem().toString().split("\\(")[0]).strip();
                    System.out.println("User id: " + secretKeyUserId);
                    PGPSecretKey secretKey = null;
                    Iterator secretKeyRingIter =  ProjectMainModel.secretKeyRingCollection.getKeyRings();
                    while (secretKeyRingIter.hasNext()) 
                    {
                        PGPSecretKeyRing keyRing = (PGPSecretKeyRing) secretKeyRingIter.next();
                        if(keyRing.getSecretKey().getUserIDs().next().toString().equals(secretKeyUserId))                        
                              secretKey = keyRing.getSecretKey();
                    }        
                    if(secretKey != null)
                        System.out.println("Secret key: " + Long.toHexString(secretKey.getKeyID()));  
                    
                    char[] password = encryptWindow.getPassField().getPassword();
                    PGPPrivateKey pgpPrivKey = null;
                    try {
                        pgpPrivKey = secretKey.extractPrivateKey
                        (new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password));
                    } catch (PGPException ex) {
                        Logger.getLogger(EncryptionController.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            });
        } 
    }
    
    public static void Encrypt(File file, Boolean sign, PGPSecretKey secretKey, char[] pass, Boolean encrpyt, PGPPublicKey publicKey)
    {
        // add Bouncy JCE Provider, http://bouncycastle.org/latest_releases.html
	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	
	// fajl koji kriptujem
	InputStream fileToEncrypt = null;
	try {
		fileToEncrypt = new FileInputStream(file);
	} catch (FileNotFoundException e) {
	}
	// fajl u koji cemo smestiti kriptovanu poruku
	OutputStream targetFileStream = null;
	try {
		targetFileStream = new FileOutputStream(new File("C:\\Users\\Korisnik\\Desktop\\test.pgp"));
	} catch (FileNotFoundException e) {

	}
	
	String targetFileName = "decript.txt";
	String outputFileName = "test.pgp";
	
	
	try {
		fEncryptOnePassSignatureLocal(file.getName(), outputFileName, 
				secretKey, targetFileStream, pass, publicKey, fileToEncrypt);
	} catch (Exception e) {
            // TODO Auto-generated catch block

	}
    }

	
    public static void fEncryptOnePassSignatureLocal(String targetFileName,
	   String outputFileName, PGPSecretKey pgpSecKey,
	    OutputStream targetFileStream, char[] password,   
	   PGPPublicKey encKey, InputStream contentStream) throws Exception 
         {
	  // ** INIT
	  int BUFFER_SIZE = 1 << 16; // should always be power of 2(one shifted bitwise 16 places)
	  //for now we will always do integrity checks and armor file
	  boolean armor = true;
	  boolean withIntegretyCheck = true;
	  //set default provider, we will pass this along
	  BouncyCastleProvider bcProvider = new BouncyCastleProvider();

	  // armor stream if set
	  if (armor)
	   targetFileStream = new ArmoredOutputStream(targetFileStream);


	// Encryption process.
	PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
	        new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                .setWithIntegrityPacket(withIntegretyCheck)
                .setSecureRandom(new SecureRandom())
                .setProvider("BC"));
        
	encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
	  
	OutputStream encryptedOut = encryptedDataGenerator.open(targetFileStream, new byte[BUFFER_SIZE]);

	  // start compression
	  PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(
	    CompressionAlgorithmTags.ZIP);
	  OutputStream compressedOut = compressedDataGenerator.open(encryptedOut);

	  //start signature
	  //PGPSecretKeyRingCollection pgpSecBundle = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(secretKeyRingInputStream));
	  //PGPSecretKey pgpSecKey = pgpSecBundle.getSecretKey(keyId);
	 
	  
	// Unlock the private key using the password
	PGPPrivateKey pgpPrivKey = pgpSecKey
			.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
					.setProvider("BC").build(password));

	// Signature generator, we can generate the public key from the private
	// key! Nifty!
	PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
			new JcaPGPContentSignerBuilder(pgpSecKey.getPublicKey()
					.getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

	signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

	  // iterate to find first signature to use
	  for (@SuppressWarnings("rawtypes")
	  Iterator i = pgpSecKey.getPublicKey().getUserIDs(); i.hasNext();) {
	   String userId = (String) i.next();
	   PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
	   spGen.setSignerUserID(false, userId);
	   signatureGenerator.setHashedSubpackets(spGen.generate());
	   // Just the first one!
	   break;
	  }
	  signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

	  // Create the Literal Data generator output stream
	  PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
	  // get file handle
	  File outputFile = new File(targetFileName);
	  // create output stream
	  OutputStream literalOut = literalDataGenerator.open(compressedOut,
	    PGPLiteralData.BINARY, outputFileName,
	    new Date(outputFile.lastModified()), new byte[BUFFER_SIZE]);
	  
	  
	  // read input file and write to target file using a buffer
	  byte[] buf = new byte[BUFFER_SIZE];
	  int len;
	  while ((len = contentStream.read(buf, 0, buf.length)) > 0) {
	   literalOut.write(buf, 0, len);
	   signatureGenerator.update(buf, 0, len);
	  }
	  // close everything down we are done
	  literalOut.close();
	  literalDataGenerator.close();
	  signatureGenerator.generate().encode(compressedOut);
	  compressedOut.close();
	  compressedDataGenerator.close();
	  encryptedOut.close();
	  encryptedDataGenerator.close();
	  

	  if (armor) targetFileStream.close();

    }
	
}

