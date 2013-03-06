package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;

/**
 * Shows the certification request to the certifying authority for 
 * approval and eventual modification.
 * 
 * @author francis
 *
 */
public class CertificationRequestApprovalActionProcessor implements
		ActionProcessor {

	@Override
	public void process(ActionContext feedbackContext) {

		
//		if(issuerKeyId==null)
//			issuerKeyId = KeyIdUtils.getSubjectKeyIdentifierAsByteString(issuerX509CertificateHolder);
//		
//		Provider provider = ProviderUtils.bcProvider;
//		
//		PKIBody pkiBody = pkiMessage.getBody();
//		
//		PKIHeader pkiHeader = pkiMessage.getHeader();
//
//		CertReqMessages certReqMessages = CertReqMessages.getInstance(pkiBody
//				.getContent());
//		CertReqMsg[] certReqMsgArray = certReqMessages.toCertReqMsgArray();
//		List<CertResponse> certResponses = new ArrayList<CertResponse>();
//		
//		for (CertReqMsg certReqMsg : certReqMsgArray) {
//			CertRequest certReq = certReqMsg.getCertReq();
//			CertTemplate certTemplate = certReq.getCertTemplate();
//			X500Name issuer = certTemplate.getIssuer();
//			if(!issuerName.equals(issuer)) continue;
//
//			SubjectPublicKeyInfo subjectPublicKeyInfo = certTemplate.getPublicKey();
//			PublicKey subjectPublicKey;
//			try {
//				subjectPublicKey = PublicKeyUtils.getPublicKey(subjectPublicKeyInfo, provider);
//			} catch (Exception e) {
//				throw new IllegalStateException(e);
//			}
//
//			OptionalValidityHolder optionalValidityHolder = new OptionalValidityHolder(certTemplate.getValidity());
//			Time notBefore = optionalValidityHolder.getNotBefore();
//			Time notAfter = optionalValidityHolder.getNotAfter();
//			
//			X509CertificateHolder x509CertificateHolder = generateCertificate(
//					certTemplate.getSubject(), notBefore.getDate(), notAfter.getDate(), 
//					subjectPublicKey, issuerPrivateKey, issuerX509CertificateHolder);
//
//			JceAsymmetricKeyWrapper jceAsymmetricKeyWrapper = new JceAsymmetricKeyWrapper(subjectPublicKey);
//			OutputEncryptor encryptor;
//			try {
//			    encryptor = new JceCRMFEncryptorBuilder(PKCSObjectIdentifiers.des_EDE3_CBC).setProvider(provider).build();
//			} catch (CRMFException e) {
//			    throw new IllegalStateException(e);
//			}
//			JcaEncryptedValueBuilder jcaEncryptedValueBuilder = new JcaEncryptedValueBuilder(jceAsymmetricKeyWrapper, encryptor);
//			EncryptedValue encryptedCert;
//			try {
//				encryptedCert = jcaEncryptedValueBuilder.build(x509CertificateHolder);
//			} catch (CRMFException e) {
//				throw new IllegalStateException(e);
//			}
//			
//			CertOrEncCert certOrEncCert = new CertOrEncCert(encryptedCert);
//			CertifiedKeyPair certifiedKeyPair = new CertifiedKeyPair(certOrEncCert);
//			PKIStatusInfo status = new PKIStatusInfo(PKIStatus.granted);
//			ASN1OctetString rspInfo = null;
//			CertResponse certResponse = new CertResponse(certReq.getCertReqId(), status, 
//					certifiedKeyPair, rspInfo);
//			certResponses.add(certResponse);
//		}
//
//		CMPCertificate[] caPubs = new CMPCertificate[]{new CMPCertificate(issuerX509CertificateHolder.toASN1Structure())};
//		CertResponse[] response = certResponses.toArray(new CertResponse[certResponses.size()]);
//		CertRepMessage certRepMessage = new CertRepMessage(caPubs, response);
//		
//		GeneralName certificateRecipient = pkiHeader.getSender();
//		GeneralName certificateSender = new GeneralName(issuerName);
//
//		ProtectedPKIMessage mainMessage;
//		
//		ProtectedPKIMessageBuilder protectedPKIMessageBuilder = new ProtectedPKIMessageBuilder(certificateSender, certificateRecipient)
//				.setBody(new PKIBody(PKIBody.TYPE_CERT_REP, certRepMessage))
//				.addCMPCertificate(issuerX509CertificateHolder)
//				.setMessageTime(new Date())
//				.setSenderKID(issuerKeyId)
//				.setSenderNonce(UUIDUtils.newUUIDAsBytes())
//				.setTransactionID(pkiHeader.getTransactionID().getOctets());
//
//		ASN1OctetString senderNonce = pkiHeader.getSenderNonce();
//		if (senderNonce != null)
//			protectedPKIMessageBuilder = protectedPKIMessageBuilder
//					.setRecipNonce(senderNonce.getOctets());
//		
//		ASN1OctetString senderKID = pkiHeader.getSenderKID();
//		if (senderKID != null)
//			protectedPKIMessageBuilder = protectedPKIMessageBuilder
//					.setRecipKID(senderKID.getOctets());
//
//		ContentSigner senderSigner;
//		try {
//			senderSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(provider).build(issuerPrivateKey);
//		} catch (OperatorCreationException e) {
//			throw new IllegalStateException(e);
//		}
//
//		try {
//			mainMessage = protectedPKIMessageBuilder.build(senderSigner);
//			PKIMessage responseMessage = mainMessage.toASN1Structure();
//			pendingResponses.add(responseMessage);
//			return ResponseFactory.create(HttpStatus.SC_OK, null);
//		} catch (CMPException e) {
//			throw new IllegalStateException(e);
//		}

	}

}
