package org.adorsys.plh.pkix.core.cms.utils;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.adorsys.plh.pkix.core.x500.X500NameHelper;
import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.stores.PrivateKeyHolder;
import org.adorys.plh.pkix.core.cmp.utils.KeyIdUtils;
import org.adorys.plh.pkix.core.cmp.utils.V3CertificateUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class SignEncryptUtils {

	public static void sign(
			PrivateKeyHolder privateKeyHolder, 
			X509CertificateHolder subjectCertificate,
			InputStream inputStream, OutputStream outputStream) throws IOException
	{	
		
		Provider provider = PlhCMPSystem.getProvider();
		
		PrivateKey privateKey = privateKeyHolder.getPrivateKey(subjectCertificate);
		
        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
		try {
			ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(provider).build(privateKey);
			BcDigestCalculatorProvider digestProvider = new BcDigestCalculatorProvider();
			SignerInfoGenerator signerInfoGenerator = new SignerInfoGeneratorBuilder(digestProvider).build(sha1Signer, subjectCertificate);
			gen.addSignerInfoGenerator(signerInfoGenerator);
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

        Store certs;
		try {
			certs = new JcaCertStore(Arrays.asList(subjectCertificate));
		} catch (CertificateEncodingException e) {
			throw new IllegalStateException(e);
		}
        
        try {
			gen.addCertificates(certs);
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		}
       
        OutputStream sigOut = gen.open(outputStream,true);
    
        IOUtils.copy(inputStream, sigOut);
        IOUtils.closeQuietly(sigOut);
	}

	public static void encrypt(
			InputStream inputStream, 
			OutputStream outputStream,
			CertificateStore certificateStore, 
			String... reciepientCommonNames) throws IOException
	{	
		
		Provider provider = PlhCMPSystem.getProvider();
		
		// Check if recipient available and if not return
        List<X509Certificate > recipientCertificates = new ArrayList<X509Certificate>();
        for (String recipientCN : reciepientCommonNames) {
        	X509CertificateHolder recipietCertificateHolder = certificateStore.getCertificate(recipientCN);
        	if(recipietCertificateHolder!=null){
        		X509Certificate recipietCertificate = V3CertificateUtils.getCertificate(recipietCertificateHolder, provider);
        		recipientCertificates.add(recipietCertificate);
        	}
		}
        if(recipientCertificates.isEmpty()) throw new IllegalStateException("No recipient certificate found for recipients: " + Arrays.toString(reciepientCommonNames));

        // envelope the datastream
        CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
        
        // add recipients
        try {
	        for (X509Certificate recipient509Certificate : recipientCertificates) {
					edGen.addRecipientInfoGenerator(        				
							new JceKeyTransRecipientInfoGenerator(recipient509Certificate).setProvider(provider));
			}
        } catch (CertificateEncodingException e) {
			throw new IllegalStateException(e);
        }

        OutputStream envelopedOut;
		try {
			envelopedOut = edGen.open(
			        outputStream, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(provider).build());
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		}

        IOUtils.copy(inputStream, envelopedOut);
        IOUtils.closeQuietly(envelopedOut);
	}
	
	public static void decrypt( 
			PrivateKeyHolder subjectPrivateKeyHolder,
			String subjectCN,
			CertificateStore certificateStore,
			InputStream inputStream, OutputStream outputStream) throws IOException {
		X509CertificateHolder subjectCertificate = certificateStore.getCertificate(subjectCN);
		decrypt(subjectPrivateKeyHolder, subjectCertificate, inputStream, outputStream);
	}

	public static void decrypt( 
			PrivateKeyHolder subjectPrivateKeyHolder,
			X509CertificateHolder subjectCertificate,
			InputStream inputStream, OutputStream outputStream) throws IOException {
		CMSEnvelopedDataParser cmsEnvelopedDataParser;
		try {
			cmsEnvelopedDataParser = new CMSEnvelopedDataParser(inputStream);
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		}
        RecipientInformationStore recipients = cmsEnvelopedDataParser.getRecipientInfos();		

		byte[] thisSubjectKeyIdentifier = KeyIdUtils.getSubjectKeyIdentifierAsByteString(subjectCertificate);
        
        @SuppressWarnings("rawtypes")
		Collection recipientsColection = recipients.getRecipients();
        RecipientInformation recipient = null;
        for (Object object : recipientsColection) {
            recipient = (RecipientInformation)object;
            RecipientId recipientId = recipient.getRID();
            if(!(recipientId instanceof KeyTransRecipientId)) continue;

            KeyTransRecipientId keyTransRecipientId = (KeyTransRecipientId) recipientId;
            byte[] subjectKeyIdentifier = keyTransRecipientId.getSubjectKeyIdentifier();
            if(!Arrays.equals(thisSubjectKeyIdentifier, subjectKeyIdentifier)) continue;
            
            break;
		}

        if(recipient==null) throw new IllegalStateException("Subject " + subjectCertificate.getSubject() + " not recipient of this file");
        
        Provider provider = PlhCMPSystem.getProvider();
        CMSTypedStream contentStream;
		try {
			contentStream = recipient.getContentStream(
					new JceKeyTransEnvelopedRecipient(subjectPrivateKeyHolder.getPrivateKey(subjectCertificate)).setProvider(provider));
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		}

        InputStream encrryptedContentStream = contentStream.getContentStream();
        IOUtils.copy(encrryptedContentStream, outputStream);
        IOUtils.closeQuietly(encrryptedContentStream);
        IOUtils.closeQuietly(outputStream);
	}

	public static void verify(InputStream signedFileInputStream, 
			CertificateStore certificateStore,
			OutputStream outputStream) throws IOException {
		Provider provider = PlhCMPSystem.getProvider();
        BufferedInputStream bufferedSignedInputStream = new BufferedInputStream(signedFileInputStream);
        CMSSignedDataParser sp;
		try {
			DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(provider).build();
			sp = new CMSSignedDataParser(digestCalculatorProvider,bufferedSignedInputStream);

		} catch (OperatorCreationException e) {
			IOUtils.closeQuietly(bufferedSignedInputStream);
			throw new IllegalStateException(e);
		} catch (CMSException e) {
			IOUtils.closeQuietly(bufferedSignedInputStream);
			throw new IllegalStateException(e);
		}
		CMSTypedStream signedContent = sp.getSignedContent();
        IOUtils.copy(signedContent.getContentStream(), outputStream);

        Store certificatesStore;
        SignerInformationStore signerInfos;
		try {
			certificatesStore = sp.getCertificates();
			signerInfos = sp.getSignerInfos();
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		}
        @SuppressWarnings("rawtypes")
		Collection signers = signerInfos.getSigners();
        for (Object object : signers) {
        	SignerInformation signer = (SignerInformation)object;
        	@SuppressWarnings("rawtypes")
			Collection certCollection = certificatesStore.getMatches(signer.getSID());
        	for (Object object2 : certCollection) {
        		X509CertificateHolder cert = (X509CertificateHolder)object2;
        		
        		// Verify Certificate
        		X509CertificateHolder certificate = certificateStore.getCertificate(
        				X500NameHelper.getCN(cert.getSubject()), X500NameHelper.getCN(cert.getIssuer()));
        		if(certificate==null)throw new SecurityException("Certificate not in store");
        		
        		// Verify signature
        		boolean verified;
				try {
					verified = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(provider).build(certificate));
				} catch (OperatorCreationException e) {
					throw new IllegalStateException(e);
				} catch (CertificateException e) {
					throw new IllegalStateException(e);
				} catch (CMSException e) {
					throw new IllegalStateException(e);
				}
        		if(verified) return;
			}
		}
        throw new SecurityException("Could not verify content.");
	}

	public static void signEncrypt(
			PrivateKeyHolder privateKeyHolder, 
			X509CertificateHolder subjectCertificate,
			InputStream inputStream, 
			OutputStream outputStream,
			CertificateStore certificateStore,			
			String... reciepientCommonNames) throws IOException 
	{
		// Sign the file
		File signedFile = File.createTempFile(UUID.randomUUID().toString(), null);
		OutputStream signedOutputStream = new FileOutputStream(signedFile);
		sign(privateKeyHolder, subjectCertificate, inputStream, signedOutputStream);
		IOUtils.closeQuietly(signedOutputStream);
		
		// encrypt the file
		InputStream signedInputStream = new FileInputStream(signedFile);
		encrypt(signedInputStream, outputStream,certificateStore, reciepientCommonNames);
		IOUtils.closeQuietly(signedInputStream);
		
		signedFile.delete();
	}
	
	public static void decryptVerify(
			PrivateKeyHolder recipientPrivateKeyHolder, 
			String subjectCN, 
			CertificateStore certificateStore, InputStream inputStream, OutputStream outputStream) throws IOException {
		// Decrypt the file
		File decryptedFile = File.createTempFile(UUID.randomUUID().toString(), null);
		OutputStream decryptedOutputStream = new FileOutputStream(decryptedFile);
		decrypt(recipientPrivateKeyHolder, subjectCN, certificateStore, inputStream, decryptedOutputStream);
		IOUtils.closeQuietly(decryptedOutputStream);
		
		// Verify, writing content to output stream.
		InputStream decryptedInputStream = new FileInputStream(decryptedFile);
		verify(decryptedInputStream, certificateStore, outputStream);
		IOUtils.closeQuietly(decryptedInputStream);
		
		decryptedFile.delete();
	}

}
