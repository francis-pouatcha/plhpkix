package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.adorsys.plh.pkix.core.smime.utils.KeyAliasSelector;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.jca.PKIXParametersFactory;
import org.adorsys.plh.pkix.core.utils.store.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class CMSStreamedDecryptorVerifier2 {
	
	private KeyStore keyStore;
	private X509CRL crl;
	private CallbackHandler callbackHandler;
	private InputStream inputStream;
	
	private final BuilderChecker checker = new BuilderChecker(CMSStreamedDecryptorVerifier2.class);
	public InputStream decryptingInputStream() {
		checker.checkDirty()
			.checkNull(keyStore, callbackHandler,inputStream);//,outputStream);
		
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
        RecipientInformation recipient = null;
        PrivateKeyEntry privateKeyEntry = null;
        Map<BigInteger, RecipientInformation> recipientsBySerialNumber =new HashMap<BigInteger, RecipientInformation>();
        Map<byte[], RecipientInformation> recipientsBySubjectKeyId =new HashMap<byte[], RecipientInformation>();
        for (Object object : recipientsColection) {
            recipient = (RecipientInformation)object;
            RecipientId recipientId = recipient.getRID();
            if(!(recipientId instanceof KeyTransRecipientId)) continue;
            
            KeyTransRecipientId keyTransRecipientId = (KeyTransRecipientId) recipientId;
            recipientsBySubjectKeyId.put(keyTransRecipientId.getSubjectKeyIdentifier(), recipient);
            recipientsBySerialNumber.put(keyTransRecipientId.getSerialNumber(), recipient);
        }        
        
        recipientsBySubjectKeyId.keySet();
        Enumeration<String> aliasesEnum;
		try {
			aliasesEnum = keyStore.aliases();
		} catch (KeyStoreException e) {
			throw new IllegalStateException(e);
		}
        ArrayList<String> aliases = new ArrayList<String>();
        while (aliasesEnum.hasMoreElements()) {
			String string = (String) aliasesEnum.nextElement();
			aliases.add(string);
		}
        for (Object object : recipientsColection) {
            recipient = (RecipientInformation)object;
            RecipientId recipientId = recipient.getRID();
            if(!(recipientId instanceof KeyTransRecipientId)) continue;
            String alias = new KeyAliasSelector()
            	.addAliases(aliases)
            	.setRecipientInformation(recipient)
            	.select();
            try {
            	PasswordCallback passwordCallback = new PasswordCallback("Enter your password", false);
            	callbackHandler.handle(new Callback[]{passwordCallback});
				privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(passwordCallback.getPassword()));
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException(e);
			} catch (UnrecoverableEntryException e) {
				throw new SecurityException(e);
			} catch (KeyStoreException e) {
				throw new IllegalStateException(e);
			} catch (UnsupportedCallbackException e) {
				throw new IllegalStateException(e);
			} catch (IOException e) {
				throw new IllegalArgumentException(e);// can not access callback handler
			}
		}

        if(recipient==null || privateKeyEntry==null) throw new SecurityException("No matching private key found for recipients of this file");
        
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
	private final BuilderChecker checker2 = new BuilderChecker(CMSStreamedDecryptorVerifier2.class);
	public CMSSignedMessageValidator<CMSPart> verify(){
		checker2.checkDirty().checkNull(sp);
        Store certificatesStore;
        SignerInformationStore signerInfos;
        CMSSignedMessageValidator<CMSPart> signedMessageValidator = new CMSSignedMessageValidator<CMSPart>();
		try {
			certificatesStore = sp.getCertificates();
			signerInfos = sp.getSignerInfos();
			
			PKIXParameters params = PKIXParametersFactory.makeParams(new KeyStoreWraper(keyStore), crl);
			CertStore certificatesAndCRLs = sp.getCertificatesAndCRLs("Collection", ProviderUtils.bcProvider);
			signedMessageValidator
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
        return signedMessageValidator;
		
	}

	public CMSStreamedDecryptorVerifier2 withKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
		return this;
	}

	public CMSStreamedDecryptorVerifier2 withCrl(X509CRL crl) {
		this.crl = crl;
		return this;
	}

	public CMSStreamedDecryptorVerifier2 withCallbackHandler(CallbackHandler callbackHandler) {
		this.callbackHandler = callbackHandler;
		return this;
	}

	public CMSStreamedDecryptorVerifier2 withInputStream(InputStream inputStream) {
		this.inputStream = inputStream;
		return this;
	}
}
