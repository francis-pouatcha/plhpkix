package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.adorsys.plh.pkix.core.smime.validator.CMSPart;
import org.adorsys.plh.pkix.core.smime.validator.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.jca.PKIXParametersFactory;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class CMSVerifier {
	
	private CMSPart inputPart;
	private KeyStore keyStore;
	private X509CRL crl;
	
	private final BuilderChecker checker = new BuilderChecker(CMSVerifier.class);
	@SuppressWarnings("deprecation")
	public CMSSignedMessageValidator<CMSPart> readAndVerify() throws IOException {
		checker.checkDirty()
			.checkNull(keyStore,inputPart);
		
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
			
			PKIXParameters params = makeParams(keyStore, crl);
			CertStore certificatesAndCRLs = sp.getCertificatesAndCRLs("Collection", ProviderUtils.bcProvider);
			signedMessageValidator
				.withCerts(certificatesAndCRLs)
				.withPKIXParameters(params)
				.withSigners(signerInfos)
				.withContent(outputPart)
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
	
	public CMSVerifier withInputPart(CMSPart inputPart) {
		this.inputPart = inputPart;
		return this;
	}

	public CMSVerifier withKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
		return this;
	}

	public CMSVerifier withCrl(X509CRL crl) {
		this.crl = crl;
		return this;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private static PKIXParameters makeParams(KeyStore keyStore, X509CRL crl){
        // create PKIXparameters
        PKIXParameters param;
		try {
			param = PKIXParametersFactory.create(keyStore);
		} catch (KeyStoreException e) {
			throw new IllegalArgumentException(e);// keystore not initialized
		} catch (InvalidAlgorithmParameterException e) {
			throw new IllegalStateException(e);// keystore not initialized
		}

        // load one ore more crls from files (here we only load one crl)
        if (crl != null)
        {
            List crls = new ArrayList();
			crls.add(crl);
			CertStore certStore;
			try {
				certStore = CertStore.getInstance("Collection",
						new CollectionCertStoreParameters(crls), "BC");
				// add crls and enable revocation checking
				param.addCertStore(certStore);
				param.setRevocationEnabled(true);
			} catch (InvalidAlgorithmParameterException e) {
				throw new IllegalStateException(e);// keystore not initialized
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException(e);// keystore not initialized
			} catch (NoSuchProviderException e) {
				throw new IllegalStateException(e);// keystore not initialized
			}
        } else {
			param.setRevocationEnabled(false);
        }
        return param;
	}
}
