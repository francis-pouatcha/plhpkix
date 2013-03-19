package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.security.cert.PKIXParameters;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;

import org.adorsys.plh.pkix.core.smime.utils.PartUtils;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.jca.PKIXParametersFactory;
import org.adorsys.plh.pkix.core.utils.store.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.store.CertStoreUtils;
import org.adorsys.plh.pkix.core.utils.store.EmailSignerList;
import org.adorsys.plh.pkix.core.utils.store.ExpectedSignerList;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedParser;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class SMIMEBodyPartVerifier {

	private ContactManager contactManager;
	private MimeBodyPart signedBodyPart;

	final BuilderChecker checker = new BuilderChecker(SMIMEBodyPartVerifier.class);

	public CMSSignedMessageValidator<MimeBodyPart> readAndVerify() {
		checker.checkDirty()
			.checkNull(contactManager,signedBodyPart);
		
		SMIMESignedParser smimeSignedParser = null;
		DigestCalculatorProvider digestCalculatorProvider;
		try {
			digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(ProviderUtils.bcProvider).build();
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}
        
        // make sure this was a multipart/signed message - there should be
        // two parts as we have one part for the content that was signed and
        // one part for the actual signature.
        try {
			if (signedBodyPart.isMimeType("multipart/signed")){
			    smimeSignedParser = new SMIMESignedParser(
			    		digestCalculatorProvider, (MimeMultipart)signedBodyPart.getContent());
			} else 
			if (signedBodyPart.isMimeType("application/pkcs7-mime")){
				smimeSignedParser = new SMIMESignedParser(digestCalculatorProvider,signedBodyPart);
			} else {
				throw new IllegalArgumentException("Not a signed message");
			}
		} catch (MessagingException e) {
			throw new IllegalArgumentException(e);
		} catch (CMSException e) {
			throw new IllegalArgumentException(e);
		} catch (SMIMEException e) {
			throw new IllegalArgumentException(e);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}

        MimeBodyPart content = smimeSignedParser.getContent();

        Store certificatesStore;
        SignerInformationStore signerInfos;
        CMSSignedMessageValidator<MimeBodyPart> signedMessageValidator = new CMSSignedMessageValidator<MimeBodyPart>();
		try {
			certificatesStore = smimeSignedParser.getCertificates();
			signerInfos = smimeSignedParser.getSignerInfos();
			PKIXParameters params = PKIXParametersFactory
					.makeParams(
							contactManager.getTrustAnchors(), 
							contactManager.getCrl(), 
							contactManager.findCertStores(CertStoreUtils.toCertHolders(certificatesStore)));

			String[] fromHeader = PartUtils.getFrom(content);
	        String[] sender = PartUtils.getSender(content);
	        ExpectedSignerList signerList = new EmailSignerList(fromHeader, sender);

			signedMessageValidator
				.withCertsFromMessage(CertStoreUtils.toCertStore(certificatesStore))
				.withPKIXParameters(params)
				.withSigners(signerInfos)
				.withSignerList(signerList)
				.validate();
	        
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		} catch (SignedMailValidatorException e) {
			throw new SecurityException(e);
		}

        signedMessageValidator.setContent(content);
        return signedMessageValidator;
	}

	public SMIMEBodyPartVerifier withSignedBodyPart(MimeBodyPart signedBodyPart) {
		this.signedBodyPart = signedBodyPart;
		return this;
	}

	public SMIMEBodyPartVerifier withContactManager(ContactManager contactManager) {
		this.contactManager = contactManager;
		return this;
	}
}
