package org.adorys.plh.pkix.server.cmp.messaging.handler;

import java.io.IOException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.message.PkiMessageConformity;
import org.adorys.plh.pkix.core.cmp.utils.GeneralNameHolder;
import org.adorys.plh.pkix.core.cmp.utils.RequestVerifier;
import org.adorys.plh.pkix.core.cmp.utils.UUIDUtils;
import org.adorys.plh.pkix.core.cmp.utils.V3CertificateUtils;
import org.adorys.plh.pkix.core.cmp.utils.X509CertificateVerifier;
import org.adorys.plh.pkix.server.cmp.endentity.EndEntityCert;
import org.adorys.plh.pkix.server.cmp.endentity.EndEntityCertRepository;
import org.adorys.plh.pkix.server.cmp.endentity.EndEntityInitializer;
import org.adorys.plh.pkix.server.cmp.utils.ErrorCommand;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

@Stateless
public class InitializationRequestHandler extends CMPRequestHandler {

	@EJB
	private EndEntityCertRepository endEntityCertRepository;

	@EJB
	private EndEntityInitializer endEntityInitializer;

	@Override
	public Response handleRequest(GeneralPKIMessage pkiMessage) {

		Response checkAndInitUser = checkAndInitUser(pkiMessage);
		if(checkAndInitUser.getStatus()!=Status.OK.getStatusCode())
			return checkAndInitUser;
		
		PKIBody pkiBody = pkiMessage.getBody();
		PKIHeader pkiHeader = pkiMessage.getHeader();

		CertReqMessages certReqMessages = CertReqMessages.getInstance(pkiBody
				.getContent());
		CertReqMsg[] certReqMsgArray = certReqMessages.toCertReqMsgArray();
		List<CMPCertificate> cmpCertificates = createCertificates(certReqMsgArray);

		CMPCertificate[] caPubs = cmpCertificates
				.toArray(new CMPCertificate[cmpCertificates.size()]);
		CertResponse[] response = new CertResponse[] {};
		CertRepMessage certRepMessage = new CertRepMessage(caPubs, response);

		GeneralName senderAsRecipien = pkiHeader.getSender();
		GeneralName recipientAsSender = pkiHeader.getRecipient();

		X500Name serverX500Name = endEntityInitializer.getServerX500Name();
		List<EndEntityCert> serverSignedCerts = endEntityCertRepository
				.findEndEntityCertBySubjectAndIssuerName(serverX500Name, serverX500Name);
		if (serverSignedCerts.isEmpty()) {
			throw new IllegalStateException("Missing server certificate record");
		}

		ProtectedPKIMessage mainMessage;
		ProtectedPKIMessageBuilder protectedPKIMessageBuilder = new ProtectedPKIMessageBuilder(
				recipientAsSender, senderAsRecipien)
				.setBody(new PKIBody(PKIBody.TYPE_INIT_REP, certRepMessage))
				.addCMPCertificate(endEntityInitializer.getServerCertificate())
				.setMessageTime(new Date())
				.setSenderKID(endEntityInitializer.getServerKeyId())
				.setSenderNonce(UUIDUtils.newUUIDAsBytes())
				.setTransactionID(pkiHeader.getTransactionID().getOctets());

		ASN1OctetString senderNonce = pkiHeader.getSenderNonce();
		if (senderNonce != null)
			protectedPKIMessageBuilder = protectedPKIMessageBuilder
					.setRecipNonce(senderNonce.getOctets());
		ASN1OctetString senderKID = pkiHeader.getSenderKID();
		if (senderKID != null)
			protectedPKIMessageBuilder = protectedPKIMessageBuilder
					.setRecipKID(senderKID.getOctets());

		Provider provider = PlhCMPSystem.getProvider();
		ContentSigner senderSigner;
		try {
			senderSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption")
					.setProvider(provider).build(
							endEntityInitializer.getServerPrivateKey());
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

		try {
			mainMessage = protectedPKIMessageBuilder.build(senderSigner);
			PKIMessage responseMessage = mainMessage.toASN1Structure();
			return Response.ok(responseMessage.getEncoded(),
					PlhCMPSystem.PKIX_CMP_STRING).build();
		} catch (IOException e) {
			throw new IllegalStateException(e);
		} catch (CMPException e) {
			throw new IllegalStateException(e);
		}
	}
	
	private List<CMPCertificate> createCertificates(CertReqMsg[] certReqMsgArray){
		List<CMPCertificate> cmpCertificates = new ArrayList<CMPCertificate>();
		for (CertReqMsg certReqMsg : certReqMsgArray) {
			CertRequest certReq = certReqMsg.getCertReq();
			CertTemplate certTemplate = certReq.getCertTemplate();
			X500Name subject = certTemplate.getSubject();
			X500Name issuer = certTemplate.getIssuer();
			List<EndEntityCert> list = endEntityCertRepository
					.findEndEntityCertBySubjectAndIssuerName(subject, issuer);
			if (list.isEmpty())
				continue;
			EndEntityCert entityCert = list.iterator().next();
			byte[] certificate = entityCert.getCertificate();
			X509CertificateHolder x509CertificateHolder;
			try {
				x509CertificateHolder = new X509CertificateHolder(certificate);
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}
			CMPCertificate cmpCertificate = new CMPCertificate(
					x509CertificateHolder.toASN1Structure());
			cmpCertificates.add(cmpCertificate);
		}
		return cmpCertificates;
	}

	private X509CertificateHolder loadCertificate(X500Name subject){
		// Certificate record must exist, signed by the server
		List<EndEntityCert> certs = endEntityCertRepository.findEndEntityCertBySubjectAndIssuerName(
				subject,endEntityInitializer.getServerX500Name());
		
		if(certs.isEmpty())
			return null;
		EndEntityCert entityCert = certs.iterator().next();
		byte[] certificate = entityCert.getCertificate();
		try {
			return new X509CertificateHolder(certificate);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
	
	private Response checkAndInitUser(GeneralPKIMessage pkiMessage){
		ProtectedPKIMessage protectedPKIMessage = PkiMessageConformity.check(pkiMessage);
		PKIHeader pkiHeader = protectedPKIMessage.getHeader();
		
		X509CertificateHolder[] certificates = protectedPKIMessage.getCertificates();
		GeneralNameHolder senderHolder = new GeneralNameHolder(pkiHeader.getSender());
		boolean registerRecord = false;
		X509CertificateHolder senderCertificate=null;
		if(certificates.length>1){
			return ErrorCommand.error(Status.BAD_REQUEST, "Expecting zero or one certificate");
		} else if (certificates.length<1 || certificates[0]==null){
			senderCertificate = loadCertificate(senderHolder.getX500Name());
		} else {
			senderCertificate = certificates[0];
			if(X509CertificateVerifier.isSelfSignedBy(senderHolder.getX500Name(), senderCertificate)){
				// check validity of self signed certificate.
				HttpResponse res = X509CertificateVerifier.verifyRequest(new Date(), senderCertificate, senderCertificate);
				if(res.getStatusLine().getStatusCode()!=HttpStatus.SC_OK){
					return ErrorCommand.error(res.getStatusLine().getStatusCode(), res.getStatusLine().getReasonPhrase());
				}
				
				// Create record if request verified
				registerRecord=true;
			} else {
				senderCertificate = loadCertificate(senderHolder.getX500Name());
			}
		}
		if(senderCertificate==null)
			return ErrorCommand.error(Status.NOT_ACCEPTABLE, "Sender not registered with this server");
		
		HttpResponse res = RequestVerifier.verifyRequest(protectedPKIMessage, senderCertificate);
		if(res.getStatusLine().getStatusCode()!=HttpStatus.SC_OK){
			return ErrorCommand.error(res.getStatusLine().getStatusCode(), res.getStatusLine().getReasonPhrase());
		}
		
		// WARNING only do this after validating the certificate.
		if(registerRecord){
			endEntityCertRepository.storeEndEntityCert(senderCertificate);
			
			X509CertificateHolder serverSignedCertificate = V3CertificateUtils
					.makeV3Certificate(senderCertificate, endEntityInitializer.getServerPrivateKey(), 
							endEntityInitializer.getServerCertificate(), senderCertificate.getNotBefore(), 
							senderCertificate.getNotAfter(), PlhCMPSystem.getProvider());
			endEntityCertRepository.storeEndEntityCert(serverSignedCertificate);
		}
		
		return Response.ok().build();
	}
}
