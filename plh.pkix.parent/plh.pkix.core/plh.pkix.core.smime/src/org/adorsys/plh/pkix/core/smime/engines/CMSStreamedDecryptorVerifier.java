package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.PKIXParameters;
import java.util.List;

import org.adorsys.plh.pkix.core.smime.utils.EnvelopedDataParserUtils;
import org.adorsys.plh.pkix.core.smime.utils.RecipientAndRecipientInfo;
import org.adorsys.plh.pkix.core.smime.utils.RecipientSelector;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.jca.PKIXParametersFactory;
import org.adorsys.plh.pkix.core.utils.store.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.store.CertStoreUtils;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class CMSStreamedDecryptorVerifier {
	
	private ContactManager contactManager;
	private InputStream inputStream;
	
	private final BuilderChecker checker = new BuilderChecker(CMSStreamedDecryptorVerifier.class);
	public InputStream decryptingInputStream() {
		checker.checkDirty()
			.checkNull(contactManager,inputStream);

		CMSEnvelopedDataParser cmsEnvelopedDataParser = EnvelopedDataParserUtils.parseData(inputStream);		
		List<RecipientInformation> recipientInfoList = EnvelopedDataParserUtils.getRecipientInfosCollection(cmsEnvelopedDataParser);

        RecipientAndRecipientInfo recipientAndRecipientInfo = new RecipientSelector()
	    	.withContactManager(contactManager)
	    	.withRecipientInfosColection(recipientInfoList)
	    	.select();
        
        InputStream encrryptedContentStream;
        try {
        	CMSTypedStream contentStream = recipientAndRecipientInfo
        			.getRecipientInformation()
        			.getContentStream(recipientAndRecipientInfo.getRecipient());
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
	public CMSSignedMessageValidator<Void> verify(){
		checker2.checkDirty().checkNull(sp);
		
        Store certificatesStore;
        SignerInformationStore signerInfos;
        CMSSignedMessageValidator<Void> signedMessageValidator = new CMSSignedMessageValidator<Void>();
		try {
			certificatesStore = sp.getCertificates();
			signerInfos = sp.getSignerInfos();
			PKIXParameters params = PKIXParametersFactory.makeParams(
					contactManager.getTrustAnchors(), 
					contactManager.getCrl(), 
					contactManager.findCertStores(CertStoreUtils.toCertHolders(certificatesStore)));

			signedMessageValidator
				.withCertsFromMessage(CertStoreUtils.toCertStore(certificatesStore))
				.withPKIXParameters(params)
				.withSigners(signerInfos)
				.validate();
	        
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		} catch (SignedMailValidatorException e) {
			throw new SecurityException(e);
		}
		return signedMessageValidator;
	}

	public CMSStreamedDecryptorVerifier withContactManager(ContactManager contactManager) {
		this.contactManager = contactManager;
		return this;
	}

	public CMSStreamedDecryptorVerifier withInputStream(InputStream inputStream) {
		this.inputStream = inputStream;
		return this;
	}
}
