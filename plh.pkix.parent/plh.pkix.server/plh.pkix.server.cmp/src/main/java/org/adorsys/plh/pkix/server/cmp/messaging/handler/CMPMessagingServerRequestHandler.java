package org.adorsys.plh.pkix.server.cmp.messaging.handler;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ws.rs.core.Response;

import org.adorsys.plh.pkix.server.cmp.endentity.EndEntityCertRepository;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;

@Stateless
public class CMPMessagingServerRequestHandler extends CMPRequestHandler {
	
	@EJB
	private InitializationRequestHandler initializationRequestHandler;
	
	@EJB
	private EndEntityCertRepository endEntityRepository;
	
	@EJB
	private CertificateAnnHandler certificateAnnHandler;
	
	@EJB
	private CertificationRequestHandler certificationRequestHandler;
	
	@EJB
	private PollRequestHandler pollRequestHandler;

	@Override
	public Response handleRequest(GeneralPKIMessage generalPKIMessage) {

		PKIBody pkiBody = generalPKIMessage.getBody();
		int messageType = pkiBody.getType();
		
		switch (messageType) {
		case PKIBody.TYPE_INIT_REQ:
			// This message is directly addressed by the caller to the server. 
			// The server will directly return the requested certificate to the client.
			return initializationRequestHandler.handleRequest(generalPKIMessage);
		case PKIBody.TYPE_INIT_REP:
			// The server will rarely get this 	question, because the server doesn't 
			// request any root ca.
			break;
		case PKIBody.TYPE_CERT_REQ:
			return certificationRequestHandler.handleRequest(generalPKIMessage);
		case PKIBody.TYPE_CERT_REP:
			break;
		case PKIBody.TYPE_KEY_UPDATE_REQ:
			break;
		case PKIBody.TYPE_KEY_UPDATE_REP:
			break;
		case PKIBody.TYPE_KEY_RECOVERY_REQ:
			break;
		case PKIBody.TYPE_KEY_RECOVERY_REP:
			break;
		case PKIBody.TYPE_REVOCATION_REQ:
			break;
		case PKIBody.TYPE_REVOCATION_REP:
			break;
		case PKIBody.TYPE_CROSS_CERT_REQ:
			break;
		case PKIBody.TYPE_CROSS_CERT_REP:
			break;
		case PKIBody.TYPE_CA_KEY_UPDATE_ANN:
			break;
		case PKIBody.TYPE_CERT_ANN:
			return certificateAnnHandler.handleRequest(generalPKIMessage);
		case PKIBody.TYPE_REVOCATION_ANN:
			break;
		case PKIBody.TYPE_CRL_ANN:
			break;
		case PKIBody.TYPE_CONFIRM:
			break;
		case PKIBody.TYPE_CERT_CONFIRM:
			break;
		case PKIBody.TYPE_GEN_MSG:
			break;
		case PKIBody.TYPE_GEN_REP:
			break;
		case PKIBody.TYPE_ERROR:
			break;
		case PKIBody.TYPE_POLL_REQ:
			// poll request. Use the message id to search the response.
			// return it to the caller or another poll response if response is no
			// yet available.
			return pollRequestHandler.handleRequest(generalPKIMessage);
		case PKIBody.TYPE_POLL_REP:
			break;

		default:
			
			break;
		}

		return null;
	}

}
