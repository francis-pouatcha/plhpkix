package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class CMSStreamedDecryptorVerifier {
	
	private PrivateKeyEntry privateKeyEntry;
	private InputStream inputStream;
	
	private final BuilderChecker checker = new BuilderChecker(CMSStreamedDecryptorVerifier.class);
	public InputStream decryptingInputStream() {
		checker.checkDirty()
			.checkNull(privateKeyEntry,inputStream);//,outputStream);
		
		CMSEnvelopedDataParser cmsEnvelopedDataParser;
		try {
			cmsEnvelopedDataParser = new CMSEnvelopedDataParser(inputStream);
		} catch (CMSException e) {
			throw new IllegalArgumentException(e);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}

		RecipientInformationStore recipients = cmsEnvelopedDataParser.getRecipientInfos();		

        @SuppressWarnings("rawtypes")
		Collection recipientsColection = recipients.getRecipients();
        RecipientInformation recipient = (RecipientInformation) recipientsColection.iterator().next();
        
        InputStream encrryptedContentStream;
        try {
        	CMSTypedStream contentStream = recipient.getContentStream(
					new JceKeyTransEnvelopedRecipient(privateKeyEntry.getPrivateKey()).setProvider(ProviderUtils.bcProvider));
        	encrryptedContentStream = contentStream.getContentStream();
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {// can not read content stream
			throw new IllegalStateException(e);
		}

		try {
			DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(ProviderUtils.bcProvider).build();
			sp = new CMSSignedDataParser(digestCalculatorProvider,encrryptedContentStream);
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		}
		
		// write content to output stream
		CMSTypedStream signedContent = sp.getSignedContent();
		return signedContent.getContentStream();
        
	}
	
	private CMSSignedDataParser sp;
	private final BuilderChecker checker2 = new BuilderChecker(CMSStreamedDecryptorVerifier.class);
	public void verify(){
		checker2.checkDirty().checkNull(sp);

		SignerInformationStore signerInfos;
		try {
			signerInfos = sp.getSignerInfos();
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		}
		@SuppressWarnings("rawtypes")
		Collection signers = signerInfos.getSigners();
		SignerInformation signer = (SignerInformation)signers.iterator().next();
		boolean verified;
		try {
			verified = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(ProviderUtils.bcProvider).build((X509Certificate) privateKeyEntry.getCertificate()));
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		}
		if(!verified) throw new SecurityException("Could not verify content.");		
	}

	public CMSStreamedDecryptorVerifier withPrivateKeyEntry(PrivateKeyEntry privateKeyEntry) {
		this.privateKeyEntry = privateKeyEntry;
		return this;
	}

	public CMSStreamedDecryptorVerifier withInputStream(InputStream inputStream) {
		this.inputStream = inputStream;
		return this;
	}
}
