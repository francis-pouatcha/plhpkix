package org.adorsys.plh.pkix.server.cmp.messaging.handler;

import java.io.IOException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ws.rs.core.Response;

import org.adorsys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.server.cmp.endentity.EndEntityCert;
import org.adorsys.plh.pkix.server.cmp.endentity.EndEntityCertRepository;
import org.adorsys.plh.pkix.server.cmp.endentity.EndEntityInitializer;
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
public class CertificationRequestHandler extends CMPRequestHandler {

	@EJB
	private EndEntityCertRepository endEntityCertRepository;

	@EJB
	private EndEntityInitializer endEntityInitializer;

	@Override
	public Response handleRequest(GeneralPKIMessage pkiMessage) {

		PKIBody pkiBody = pkiMessage.getBody();
		PKIHeader pkiHeader = pkiMessage.getHeader();

		CertReqMessages certReqMessages = CertReqMessages.getInstance(pkiBody
				.getContent());
		CertReqMsg[] certReqMsgArray = certReqMessages.toCertReqMsgArray();
		List<CMPCertificate> cmpCertificates = new ArrayList<CMPCertificate>();
		for (CertReqMsg certReqMsg : certReqMsgArray) {
			CertRequest certReq = certReqMsg.getCertReq();
			CertTemplate certTemplate = certReq.getCertTemplate();
			X500Name subject = certTemplate.getSubject();
			X500Name issuer = certTemplate.getIssuer();
			List<EndEntityCert> list = endEntityCertRepository
					.findEndEntityCertBySubjectAndIssuerName(
							subject, issuer);
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
		CMPCertificate[] caPubs = cmpCertificates
				.toArray(new CMPCertificate[cmpCertificates.size()]);
		CertResponse[] response = new CertResponse[] {};
		CertRepMessage certRepMessage = new CertRepMessage(caPubs, response);
		GeneralName senderAsRecipien = pkiHeader.getSender();
		GeneralName recipientAsSender = pkiHeader.getRecipient();

		X500Name serverX500Name = PlhCMPSystem.getServerName();
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

		Provider provider = ProviderUtils.bcProvider;
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
}
