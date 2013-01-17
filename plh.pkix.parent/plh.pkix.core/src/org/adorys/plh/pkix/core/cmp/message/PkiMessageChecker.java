package org.adorys.plh.pkix.core.cmp.message;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.utils.ErrorCommand;
import org.adorys.plh.pkix.core.cmp.utils.RequestVerifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;

/**
 * Generic message processor. Load and verify the message for 
 * formal correctness and integrity. Throw an {@link IllegalStateException}
 * if the message is malformed of modified. 
 * 
 * @author francis
 *
 */
public class PkiMessageChecker {
	
	private CertificateStore certificateStore;
	
	public PkiMessageChecker withCertificateStore(CertificateStore certificateStore) {
		this.certificateStore = certificateStore;
		return this;
	}

	public Response check(GeneralPKIMessage generalPKIMessage){
		
		assert certificateStore!=null : "Field certificateStore can not be null";
		
		ProtectedPKIMessage protectedPKIMessage = PkiMessageConformity.check(generalPKIMessage);
		GeneralName sender = protectedPKIMessage.getHeader().getSender();
		
		X509CertificateHolder senderCertificate = certificateStore.getCertificate(X500Name.getInstance(sender.getName()));

		if(senderCertificate==null)return ErrorCommand.error(Status.NOT_ACCEPTABLE, "Missing sender certificate");

		Response verifiedRequest = RequestVerifier.verifyRequest(protectedPKIMessage, senderCertificate);
		if(verifiedRequest.getStatus()!=Status.OK.getStatusCode())return verifiedRequest;
		
		return Response.ok().build();
	}
}
