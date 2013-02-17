package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import org.adorsys.plh.pkix.core.smime.validator.CMSPart;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Store;

public class CMSSigner {
	private Certificate[] signerCertificateChain;
	private CMSPart inputPart;
	
	private final BuilderChecker checker = new BuilderChecker(CMSSigner.class);
	public CMSPart sign(PrivateKey privateKey) {	
		checker.checkDirty()
			.checkNull(privateKey, inputPart,signerCertificateChain)
			.checkEmpty(signerCertificateChain);
		
        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
        List<X509CertificateHolder> signerCertificateChainAsList = new ArrayList<X509CertificateHolder>(signerCertificateChain.length);
		try {
			for (int i = 0; i < signerCertificateChain.length; i++) {
				X509CertificateHolder signerCertificate = new X509CertificateHolder(signerCertificateChain[i].getEncoded());
				signerCertificateChainAsList.add(signerCertificate);
			}
			ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(ProviderUtils.bcProvider).build(privateKey);
			BcDigestCalculatorProvider digestProvider = new BcDigestCalculatorProvider();
			SignerInfoGenerator signerInfoGenerator = new SignerInfoGeneratorBuilder(digestProvider).build(sha1Signer, signerCertificateChainAsList.get(0));
			gen.addSignerInfoGenerator(signerInfoGenerator);
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		} catch (CertificateEncodingException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}

        Store certs;
		try {
			certs = new JcaCertStore(signerCertificateChainAsList);
		} catch (CertificateEncodingException e) {
			throw new IllegalStateException(e);
		}
        
        try {
			gen.addCertificates(certs);
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		}
       
		CMSPart outputPart = CMSPart.instanceEmpty();
		OutputStream sigOut;
		try {
			sigOut = gen.open(outputPart.openStream(),true);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
		inputPart.writeTo(sigOut);
		return outputPart;
	}
	
	public CMSSigner withSignerCertificateChain(Certificate[] signerCertificateChain) {
		this.signerCertificateChain = signerCertificateChain;
		return this;
	}
	public CMSSigner withInputPart(CMSPart inputPart) {
		this.inputPart= inputPart;
		return this;
	}
}
