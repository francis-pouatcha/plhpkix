package org.adorsys.plh.pkix.core.cmp.utils;

import java.security.cert.X509Certificate;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

public class RequestVerifier2 {
	private ProtectedPKIMessage protectedPKIMessage;
	private X509CertificateHolder certificateHolder;
	
	private final BuilderChecker checker = new BuilderChecker(RequestVerifier2.class);

	public ProcessingResults<Boolean> verify(){
    	checker.checkDirty()
    		.checkNull(protectedPKIMessage, certificateHolder);
    	
		X509Certificate jcaCert = V3CertificateUtils.getX509JavaCertificate(certificateHolder);
		
        ContentVerifierProvider verifierProvider;
		try {
			verifierProvider = new JcaContentVerifierProviderBuilder()
				.setProvider(ProviderUtils.bcProvider).build(jcaCert.getPublicKey());
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

		boolean verify;
		ProcessingResults<Boolean> processingResults = new ProcessingResults<Boolean>();

		try {
			verify = protectedPKIMessage.verify(verifierProvider);
			processingResults.setReturnValue(verify);
			return processingResults;
		} catch (CMPException e) {
			throw new IllegalStateException(e);
		}
    }

	public RequestVerifier2 withProtectedPKIMessage(ProtectedPKIMessage protectedPKIMessage) {
		this.protectedPKIMessage = protectedPKIMessage;
		return this;
	}

	public RequestVerifier2 withCertificateHolder(X509CertificateHolder certificateHolder) {
		this.certificateHolder = certificateHolder;
		return this;
	}
}
