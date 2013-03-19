package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.security.cert.PKIXParameters;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.jca.PKIXParametersFactory;
import org.adorsys.plh.pkix.core.utils.store.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.store.CertStoreUtils;
import org.adorsys.plh.pkix.core.utils.store.ExpectedSignerList;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class CMSVerifier {
	
	private ContactManager contactManager;
	private CMSPart inputPart;
	private ExpectedSignerList signerList;
	
	private final BuilderChecker checker = new BuilderChecker(CMSVerifier.class);
	public CMSSignedMessageValidator<CMSPart> readAndVerify() throws IOException {
		checker.checkDirty()
			.checkNull(contactManager,inputPart);
		
        CMSSignedDataParser sp;
		try {
			DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(ProviderUtils.bcProvider).build();
			sp = new CMSSignedDataParser(digestCalculatorProvider,inputPart.newInputStream());
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		}
		
		// write content to output stream
		CMSTypedStream signedContent = sp.getSignedContent();
		CMSPart outputPart = CMSPart.instanceFrom(signedContent.getContentStream());
        
        Store certificatesStore;
        SignerInformationStore signerInfos;
        CMSSignedMessageValidator<CMSPart> signedMessageValidator = new CMSSignedMessageValidator<CMSPart>();
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
				.withContent(outputPart)
				.withSignerList(signerList)
				.validate();
	        
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		} catch (SignedMailValidatorException e) {
			throw new SecurityException(e);
		}

        return signedMessageValidator;
	}
	
	public CMSVerifier withInputPart(CMSPart inputPart) {
		this.inputPart = inputPart;
		return this;
	}

	public CMSVerifier withSignerList(ExpectedSignerList signerList) {
		this.signerList = signerList;
		return this;
	}

	public CMSVerifier withContactManager(ContactManager contactManager) {
		this.contactManager = contactManager;
		return this;
	}
}
