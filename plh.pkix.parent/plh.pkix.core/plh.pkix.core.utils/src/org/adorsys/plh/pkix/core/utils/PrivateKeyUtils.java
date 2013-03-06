package org.adorsys.plh.pkix.core.utils;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;

public class PrivateKeyUtils {

	public static byte[] encryptPrivateKey(PrivateKey privateKey, Provider provider, char[] password) throws Exception{

		byte[] privateKeyBytes = privateKeyToBytes(privateKey, provider);
		CMSTypedData content = new CMSProcessableByteArray(privateKeyBytes);

		CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

		JcePasswordRecipientInfoGenerator recipientInfoGenerator = new JcePasswordRecipientInfoGenerator(CMSAlgorithm.DES_EDE3_CBC, password).setProvider(provider);
		edGen.addRecipientInfoGenerator(recipientInfoGenerator);
		CMSEnvelopedData ed = edGen.generate(content,new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(provider).build());

		return ed.getEncoded();
		
	}
	
	public static PrivateKey decryptPrivateKey(byte[] encryptedPrivateKey, char[] password, Provider provider) throws Exception {

		CMSEnvelopedDataParser cmsEnvelopedDataParser = new CMSEnvelopedDataParser(encryptedPrivateKey);

        RecipientInformationStore recipients = cmsEnvelopedDataParser.getRecipientInfos();
        @SuppressWarnings("rawtypes")
		Collection envCollection = recipients.getRecipients();
        @SuppressWarnings("rawtypes")
		Iterator it = envCollection.iterator();
        RecipientInformation recipientInformation = (RecipientInformation) it.next();
        JcePasswordEnvelopedRecipient recipient = new JcePasswordEnvelopedRecipient(password);
        
        byte[] privateKeyBytes = recipientInformation.getContent(recipient);
        		
        return privateKeyFromBytes(privateKeyBytes, provider);
	}
	
	public static PrivateKey privateKeyFromBytes(byte[] privateKeyBytes, Provider provider) throws InvalidKeySpecException, IOException {

		PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKeyBytes);
        
		PKCS8EncodedKeySpec pKCS8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());

        try {
			return KeyFactory.getInstance(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().getId(), provider).generatePrivate(pKCS8EncodedKeySpec);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}
	
	public static byte[] privateKeyToBytes(PrivateKey privateKey, Provider provider) {
		return privateKey.getEncoded();
	}
	
	public static final PrivateKey clonePrivateKey(PrivateKey privateKey){
		byte[] privateKeyBytes = privateKeyToBytes(privateKey, ProviderUtils.bcProvider);
		try {
			return privateKeyFromBytes(privateKeyBytes, ProviderUtils.bcProvider);
		} catch (InvalidKeySpecException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
//	
//	public static X509CertificateHolder getX509CertificateHolder(PrivateKeyEntry privateKeyEntry){
//		try {
//			return new X509CertificateHolder(privateKeyEntry.getCertificate().getEncoded());
//		} catch (CertificateEncodingException e) {
//			throw new IllegalArgumentException(e);
//		} catch (IOException e) {
//			throw new IllegalStateException(e);
//		}
//		
//		
//	}
}
