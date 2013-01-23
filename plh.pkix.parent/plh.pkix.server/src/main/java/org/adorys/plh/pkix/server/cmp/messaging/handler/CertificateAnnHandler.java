package org.adorys.plh.pkix.server.cmp.messaging.handler;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ws.rs.core.Response;

import org.adorys.plh.pkix.core.cmp.utils.RequestVerifier;
import org.adorys.plh.pkix.server.cmp.endentity.EndEntityCertRepository;
import org.adorys.plh.pkix.server.cmp.utils.ErrorCommand;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;

@Stateless
public class CertificateAnnHandler  extends CMPRequestHandler {

	@EJB
	private EndEntityCertRepository endEntityRepository;

	@Override
	public Response handleRequest(GeneralPKIMessage pkiMessage) {

		PKIBody pkiBody = pkiMessage.getBody();
		
		// Read the content of the message
		CMPCertificate cmpCertificate = CMPCertificate.getInstance(pkiBody.getContent());
		X509CertificateHolder cmpCertificateHolder = new X509CertificateHolder(cmpCertificate.getX509v3PKCert());
		
		// The certificate being stored must be the one used to sign
		// this request. This is the proof that the request was sent 
		// by the subject of the certificate.
		ProtectedPKIMessage protectedPKIMessage = new ProtectedPKIMessage(pkiMessage);
		HttpResponse res = RequestVerifier.verifyRequest(protectedPKIMessage, cmpCertificateHolder);
		if(res.getStatusLine().getStatusCode()!=HttpStatus.SC_OK){
			return ErrorCommand.error(res.getStatusLine().getStatusCode(), res.getStatusLine().getReasonPhrase());
		}

		endEntityRepository.storeEndEntityCert(cmpCertificateHolder);

		return Response.ok().build();
	}
}
