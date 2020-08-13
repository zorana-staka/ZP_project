package controller;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPairGenerator;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

import view.NewKeyPairWindow;

public class NewKeyPairGenController implements ActionListener
{
	public void actionPerformed(ActionEvent e)
	{
		NewKeyPairWindow newKeyPairWindow = new NewKeyPairWindow();
		newKeyPairWindow.setVisible(true);
		newKeyPairWindow.addWindowListener(new WindowAdapter() 
		{
			public void windowClosed(WindowEvent windowEvent)
			{
				int keySize = Integer.parseInt(newKeyPairWindow.getCbKeySize().getSelectedItem().toString().substring(0, 4));
				String name = newKeyPairWindow.getTxtFieldName().getText();
                                String email = newKeyPairWindow.getTxtFieldEmail().getText();
                                char[] password = {'z', 'o'};
                            try {
                                generateNewKeyPair(name, email, keySize, password);
                            } catch (Exception ex) {
                                Logger.getLogger(NewKeyPairGenController.class.getName()).log(Level.SEVERE, null, ex);
                            }
                                System.out.println(name);
			}
		});
	}
	
	public void generateNewKeyPair(String name, String email, int length, char[] password) throws FileNotFoundException, IOException, Exception
	{
		Date start = new Date();
		System.out.println("Početak: " + start.toString());
		KeyPairGenerator keyPairGen;
                PGPKeyRingGenerator krgen = generateKeyRingGenerator(email, password, 0xc0);
                // Generate public key ring, dump to file.
                PGPPublicKeyRing pkr = krgen.generatePublicKeyRing();
                
                ArmoredOutputStream pubout = new ArmoredOutputStream(new FileOutputStream("C:\\Users\\Korisnik\\Desktop\\test.asc"));
                pkr.encode(pubout);
                pubout.close();

                // Generate private key, dump to file.
                PGPSecretKeyRing skr = krgen.generateSecretKeyRing();

                BufferedOutputStream secout = new BufferedOutputStream
                    (new FileOutputStream("C:\\Users\\Korisnik\\Desktop\\test2.asc"));
                skr.encode(secout);
                secout.close();

                System.out.println("Kraj: " + (new Date()).toString());
	}
        
        public final static PGPKeyRingGenerator generateKeyRingGenerator
        (String id, char[] pass, int s2kcount)
        throws Exception
        {
            // This object generates individual key-pairs.
            RSAKeyPairGenerator  kpg = new RSAKeyPairGenerator();

            // Boilerplate RSA parameters, no need to change anything
            // except for the RSA key-size (2048). You can use whatever
            // key-size makes sense for you -- 4096, etc.
            kpg.init
                (new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001),
                new SecureRandom(), 2048, 12));

            // First create the master (signing) key with the generator.
            PGPKeyPair rsakp_sign = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), new Date());
            // Then an encryption subkey.
            PGPKeyPair rsakp_enc = new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), new Date());

            // Add a self-signature on the id
            PGPSignatureSubpacketGenerator signhashgen = new PGPSignatureSubpacketGenerator();

            // Add signed metadata on the signature.
            // 1) Declare its purpose
            signhashgen.setKeyFlags(false, KeyFlags.SIGN_DATA|KeyFlags.CERTIFY_OTHER);
            // 2) Set preferences for secondary crypto algorithms to use
            //    when sending messages to this key.
            signhashgen.setPreferredSymmetricAlgorithms
                (false, new int[] {SymmetricKeyAlgorithmTags.AES_256,
                    SymmetricKeyAlgorithmTags.AES_192,
                    SymmetricKeyAlgorithmTags.AES_128
                });
            signhashgen.setPreferredHashAlgorithms
                (false, new int[] { HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA1,
                    HashAlgorithmTags.SHA384,
                    HashAlgorithmTags.SHA512,
                    HashAlgorithmTags.SHA224,
                });
            // 3) Request senders add additional checksums to the
            //    message (useful when verifying unsigned messages.)
            signhashgen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

            // Create a signature on the encryption subkey.
            PGPSignatureSubpacketGenerator enchashgen = new PGPSignatureSubpacketGenerator();
            // Add metadata to declare its purpose
            enchashgen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS|KeyFlags.ENCRYPT_STORAGE);

            // Objects used to encrypt the secret key.
            PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
            PGPDigestCalculator sha256Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);

            // bcpg 1.48 exposes this API that includes s2kcount. Earlier
            // versions use a default of 0x60.
            PBESecretKeyEncryptor pske = (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc, s2kcount))
                .build(pass);

            // Finally, create the keyring itself. The constructor
            // takes parameters that allow it to generate the self
            // signature.
            PGPKeyRingGenerator keyRingGen =
                new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsakp_sign,
                 id, sha1Calc, signhashgen.generate(), null, new BcPGPContentSignerBuilder
                 (rsakp_sign.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                 pske);

            // Add our encryption subkey, together with its signature.
            keyRingGen.addSubKey
                (rsakp_enc, enchashgen.generate(), null);
            
            
                ByteArrayOutputStream encOut = new ByteArrayOutputStream();
                ArmoredOutputStream armorOut = new ArmoredOutputStream(encOut);  
    
                armorOut.write(rsakp_sign.getPublicKey().getEncoded());
                armorOut.flush();
                armorOut.close();
                System.out.println(new String(encOut.toByteArray()));
            
            return keyRingGen;
    }
}

