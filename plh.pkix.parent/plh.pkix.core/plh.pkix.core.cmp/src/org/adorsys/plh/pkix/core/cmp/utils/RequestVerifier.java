package org.adorsys.plh.pkix.core.cmp.utils;

import java.security.cert.X509Certificate;

import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

public abstract class RequestVerifier {

	/**
	 * Verifies a request. A request must be either password protected or 
	 * signed. This framework does not accept unprotected messages.
	 * 
	 * @param generalPKIMessage
	 * @return
	 */
    public static HttpResponse verifyRequest(ProtectedPKIMessage protectedPKIMessage, X509CertificateHolder certificateHolder){

		X509Certificate jcaCert = V3CertificateUtils.getX509JavaCertificate(certificateHolder);

        ContentVerifierProvider verifierProvider;
		try {
			verifierProvider = new JcaContentVerifierProviderBuilder()
				.setProvider(ProviderUtils.bcProvider).build(jcaCert.getPublicKey());
		} catch (OperatorCreationException e) {
			return ResponseFactory.create(HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getMessage());
		}

		boolean verify;

		try {
			verify = protectedPKIMessage.verify(verifierProvider);
		} catch (CMPException e) {
			return ResponseFactory.create(HttpStatus.SC_NOT_ACCEPTABLE, e.getMessage());
		}

		if(!verify){
			return ResponseFactory.create(HttpStatus.SC_NOT_ACCEPTABLE, "Could not verify message");
		}
		
		return ResponseFactory.create(HttpStatus.SC_OK, null);
    }
}
