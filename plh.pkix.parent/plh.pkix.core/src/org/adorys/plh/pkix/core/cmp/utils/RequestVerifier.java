package org.adorys.plh.pkix.core.cmp.utils;

import java.security.Provider;
import java.security.cert.X509Certificate;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
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
    public static Response verifyRequest(ProtectedPKIMessage protectedPKIMessage, X509CertificateHolder certificateHolder){

    	Provider provider = PlhCMPSystem.getProvider();
    	
		X509Certificate jcaCert = V3CertificateUtils.getCertificate(certificateHolder, provider);

        ContentVerifierProvider verifierProvider;
		try {
			verifierProvider = new JcaContentVerifierProviderBuilder()
				.setProvider(provider).build(jcaCert.getPublicKey());
		} catch (OperatorCreationException e) {
			return ErrorCommand.error(Status.INTERNAL_SERVER_ERROR, e.getMessage());
		}

		boolean verify;

		try {
			verify = protectedPKIMessage.verify(verifierProvider);
		} catch (CMPException e) {
			return ErrorCommand.error(Status.NOT_ACCEPTABLE, e.getMessage());
		}

		if(!verify){
			return ErrorCommand.error(Status.NOT_ACCEPTABLE, "Could not verify message");
		}
		
		return Response.ok(protectedPKIMessage).build();
    }
}
