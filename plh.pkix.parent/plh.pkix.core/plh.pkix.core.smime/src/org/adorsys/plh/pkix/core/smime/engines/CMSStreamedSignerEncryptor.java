package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.adorsys.plh.pkix.core.smime.utils.CloseSubstreamsOutputStream;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Store;

public class CMSStreamedSignerEncryptor {

	private List<X509Certificate> recipientCertificates;
	
	private OutputStream outputStream;
	
	private final BuilderChecker checker = new BuilderChecker(CMSStreamedSignerEncryptor.class);
	public OutputStream signingEncryptingOutputStream(PrivateKeyEntry privateKeyEntry) {
		checker.checkDirty()
			.checkNull(privateKeyEntry, recipientCertificates)
			.checkEmpty(recipientCertificates);

		// envelope the dataStream
        CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
        // add recipients
        try {
	        for (X509Certificate recipient509Certificate : recipientCertificates) {
					edGen.addRecipientInfoGenerator(        				
							new JceKeyTransRecipientInfoGenerator(recipient509Certificate).setProvider(ProviderUtils.bcProvider));
			}
        } catch (CertificateEncodingException e) {
			throw new IllegalStateException(e);
        }

        OutputStream  envelopedOut;
		try {
			envelopedOut = edGen.open(outputStream, 
					new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(ProviderUtils.bcProvider).build());
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}

        CMSSignedDataStreamGenerator sGen = new CMSSignedDataStreamGenerator();
        Certificate[] signerCertificateChain = privateKeyEntry.getCertificateChain();
        List<X509CertificateHolder> signerCertificateChainAsList = new ArrayList<X509CertificateHolder>(signerCertificateChain.length);
        for (int i = 0; i < signerCertificateChain.length; i++) {
        	X509CertificateHolder signerCertificate = V3CertificateUtils.getX509CertificateHolder(signerCertificateChain[i]);
        	signerCertificateChainAsList.add(signerCertificate);
        }
		try {
			ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(ProviderUtils.bcProvider).build(privateKeyEntry.getPrivateKey());
			BcDigestCalculatorProvider digestProvider = new BcDigestCalculatorProvider();
			SignerInfoGenerator signerInfoGenerator = new SignerInfoGeneratorBuilder(digestProvider).build(sha1Signer, signerCertificateChainAsList.get(0));
			sGen.addSignerInfoGenerator(signerInfoGenerator);
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

        Store certs;
		try {
			certs = new JcaCertStore(signerCertificateChainAsList);
		} catch (CertificateEncodingException e) {
			throw new IllegalStateException(e);
		}
        
        try {
			sGen.addCertificates(certs);
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		}
       
		OutputStream sigOut;
		try {
			sigOut = sGen.open(envelopedOut,true);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
		
		CloseSubstreamsOutputStream closeSubstreamsOutputStream = new CloseSubstreamsOutputStream(sigOut);
		closeSubstreamsOutputStream.addSubStream(envelopedOut);
		return closeSubstreamsOutputStream;
	}

	public CMSStreamedSignerEncryptor withRecipientCertificates(List<X509Certificate> recipientCertificates) {
		this.recipientCertificates = recipientCertificates;
		return this;
	}

	public CMSStreamedSignerEncryptor withOutputStream(OutputStream outputStream) {
		this.outputStream = outputStream;
		return this;
	}
}
