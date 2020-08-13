/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package controller;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import model.projectMainClass;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openssl.PEMDecryptor;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.util.encoders.Base64Encoder;

/**
 *
 * @author Korisnik
 */
public class KeysController 
{
    public static void createKeyRings()
    {
        
    }
    
    public static void getPublicKeys() throws IOException
    {
        File publicFolder = new File(projectMainClass.pathPublicKeyFile);
        File[] listOfFiles = publicFolder.listFiles();
        for(File file : listOfFiles)
        {
            if(file.isFile())
                generatePublicKey(file);
        }
    }
    
    public static void generatePublicKey(File file) throws FileNotFoundException, IOException
    {
        Base64Encoder encoder = new Base64Encoder();
        PEMParser pemParser = new PEMParser(new FileReader(file));
        
        //Object object = pemParser.readObject();
        //PEMDecryptorProvider pemDecryptorProvider = new JcePEMDecryptorProviderBuilder().build(null);
        //JcaPEMKeyConverter pemKeyConverter = new JcaPEMKeyConverter().setProvider("BC");
        //PGPPublicKey publicKey;
        //publicKey = (PGPPublicKey) pemKeyConverter.getPublicKey((SubjectPublicKeyInfo) object);
        //System.out.println(publicKey.toString());
    }
}
