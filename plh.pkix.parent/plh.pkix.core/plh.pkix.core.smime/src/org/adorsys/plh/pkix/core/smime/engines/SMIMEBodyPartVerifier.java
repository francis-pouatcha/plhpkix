package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.mail.MessagingException;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;

import org.adorsys.plh.pkix.core.smime.utils.PartUtils;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.jca.PKIXParametersFactory;
import org.adorsys.plh.pkix.core.utils.store.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.store.EmailAddressExtractor;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedParser;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class SMIMEBodyPartVerifier {

	private KeyStore keyStore;
	private X509CRL crl;
	private MimeBodyPart signedBodyPart;

	final BuilderChecker checker = new BuilderChecker(SMIMEBodyPartVerifier.class);
	@SuppressWarnings("deprecation")
	public CMSSignedMessageValidator<MimeBodyPart> readAndVerify() {
		checker.checkDirty()
			.checkNull(keyStore,signedBodyPart);
		
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
			
			PKIXParameters params = PKIXParametersFactory.makeParams(new KeyStoreWraper(keyStore), crl);
			CertStore certificatesAndCRLs = smimeSignedParser.getCertificatesAndCRLs("Collection", ProviderUtils.bcProvider);
			List<String> senders = new ArrayList<String>();
	        String[] fromHeader = PartUtils.getFrom(content);
	        processSender(fromHeader, senders);
	        String[] sender = PartUtils.getSender(content);
	        processSender(sender, senders);

			signedMessageValidator
				.withSenders(senders)
				.withCertInfoExtractor(new EmailAddressExtractor()) 
				.withCerts(certificatesAndCRLs)
				.withPKIXParameters(params)
				.withSigners(signerInfos)
				.validate();
	        
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		} catch (SignedMailValidatorException e) {
			throw new SecurityException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		} catch (NoSuchProviderException e) {
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

        		// Verify signature
        		boolean verified;
				try {
					verified = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(ProviderUtils.bcProvider).build(cert));
				} catch (OperatorCreationException e) {
					throw new IllegalStateException(e);
				} catch (CertificateException e) {
					throw new IllegalStateException(e);
				} catch (CMSException e) {
					throw new IllegalStateException(e);
				}
				if(!verified) throw new SecurityException("Could not verify content.");
			}
		}
        signedMessageValidator.setContent(content);
        return signedMessageValidator;
	}

	public SMIMEBodyPartVerifier withKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
		return this;
	}

	public SMIMEBodyPartVerifier withCrl(X509CRL crl) {
		this.crl = crl;
		return this;
	}

	public SMIMEBodyPartVerifier withSignedBodyPart(MimeBodyPart signedBodyPart) {
		this.signedBodyPart = signedBodyPart;
		return this;
	}

	private void processSender(String[] fromHeader, final List<String> senders){
		if(fromHeader!=null){
			for (String from : fromHeader) {
				InternetAddress[] parsedHeader;
				try {
					parsedHeader = InternetAddress.parseHeader(from, true);
					for (InternetAddress internetAddress : parsedHeader) {
						senders.add(internetAddress.getAddress());
					}
				} catch (AddressException e) {
					senders.add(from);
				}
			}
		} 
	}
}
