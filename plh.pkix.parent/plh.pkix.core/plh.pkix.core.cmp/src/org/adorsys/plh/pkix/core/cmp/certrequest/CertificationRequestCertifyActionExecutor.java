package org.adorsys.plh.pkix.core.cmp.certrequest;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.utils.OptionalValidityHolder;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyUsageUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.PublicKeyUtils;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.jca.X509CertificateBuilder;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Uses the ca private key of the certification authority to create a certificate and 
 * return it with the corresponding certificate chain.
 * 
 * @author francis
 *
 */
public class CertificationRequestCertifyActionExecutor {
	
	private CertTemplate certTemplate;
	
	private final BuilderChecker checker = new BuilderChecker(CertificationRequestCertifyActionExecutor.class);
	public ProcessingResults<List<X509CertificateHolder>> execute(KeyStoreWraper keyStoreWraper){
		checker.checkDirty()
			.checkNull(certTemplate,keyStoreWraper);
		// this is the serial number of the certificate used by the issuer 
		// to sign this certificate.
		BigInteger serialNumber = certTemplate.getSerialNumber().getPositiveValue();
		PrivateKeyEntry privateKeyEntry = keyStoreWraper.findKeyEntryBySerialNumber(serialNumber);

		SubjectPublicKeyInfo subjectPublicKeyInfo = certTemplate.getPublicKey();
		PublicKey subjectPublicKey;
		try {
			subjectPublicKey = PublicKeyUtils.getPublicKey(subjectPublicKeyInfo, ProviderUtils.bcProvider);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}

		OptionalValidityHolder optionalValidityHolder = new OptionalValidityHolder(certTemplate.getValidity());
		Time notBefore = optionalValidityHolder.getNotBefore();
		Time notAfter = optionalValidityHolder.getNotAfter();
		X509Certificate issuerCertificate = (X509Certificate) privateKeyEntry.getCertificate();
		X509CertificateHolder issuerCertificateHolder;
		try {
			issuerCertificateHolder = new X509CertificateHolder(issuerCertificate.getEncoded());
		} catch (CertificateEncodingException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
		
		X509CertificateBuilder certificateBuilder = new X509CertificateBuilder()
			.withIssuerCertificate(issuerCertificateHolder)
			.withNotAfter(notAfter.getDate())
			.withNotBefore(notBefore.getDate())
			.withSubjectDN(certTemplate.getSubject())
			.withSubjectPublicKey(subjectPublicKey);

		Extensions extensions = certTemplate.getExtensions();
		Extension basicConstraintsExtension = extensions.getExtension(X509Extension.basicConstraints);
		BasicConstraints basicConstraints = BasicConstraints.getInstance(basicConstraintsExtension.getParsedValue());
		boolean ca = basicConstraints.isCA();
		certificateBuilder = certificateBuilder.withCa(ca);

		Extension extension1 = extensions.getExtension(X509Extension.subjectAlternativeName);
		if(extension1!=null) {
			GeneralNames subjectAltName = GeneralNames.getInstance(extension1.getParsedValue());
			if(subjectAltName!=null)certificateBuilder = certificateBuilder.withSubjectAltNames(subjectAltName);
		}
		
		int keyUsage = KeyUsageUtils.getKeyUsage(extensions);
		if(keyUsage>-1){
			certificateBuilder = certificateBuilder.withKeyUsage(keyUsage);
		}
		
		Extension extension2 = extensions.getExtension(X509Extension.authorityInfoAccess);
		if(extension2!=null){
			AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(extension2.getParsedValue());
			if(authorityInformationAccess!=null)
				certificateBuilder = certificateBuilder.withAuthorityInformationAccess(authorityInformationAccess);
		}
		X509CertificateHolder x509CertificateHolder = certificateBuilder.build(privateKeyEntry.getPrivateKey());
		List<X509CertificateHolder> result = new ArrayList<X509CertificateHolder>();
		result.add(x509CertificateHolder);// 0 the subject certificate
		result.add(issuerCertificateHolder);// 1 the issuer certificate
		Certificate[] certificateChain = privateKeyEntry.getCertificateChain();
		for (Certificate certificate : certificateChain) {
			if(issuerCertificate.equals(certificate)) continue;// already in
			X509Certificate cert = (X509Certificate) certificate;
			X509CertificateHolder ch;
			try {
				ch = new X509CertificateHolder(cert.getEncoded());
			} catch (CertificateEncodingException e) {
				throw new IllegalStateException(e);
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}
			result.add(ch);
		}
		ProcessingResults<List<X509CertificateHolder>> processingResults = new ProcessingResults<List<X509CertificateHolder>>();
		processingResults.setReturnValue(result);
		return processingResults;
		
//		List<CertResponse> certResponses = new ArrayList<CertResponse>();
		
//		PKIBody pkiBody = generalPKIMessage.getBody();
//		
//		PKIHeader pkiHeader = generalPKIMessage.getHeader();
//
//		CertReqMessages certReqMessages = CertReqMessages.getInstance(pkiBody
//				.getContent());
//		CertReqMsg[] certReqMsgArray = certReqMessages.toCertReqMsgArray();
//		CertReqMsg certReqMsg = certReqMsgArray[0];
//		CertRequest certReq = certReqMsg.getCertReq();
//		CertTemplate certTemplate = certReq.getCertTemplate();
//
//
//		JceAsymmetricKeyWrapper jceAsymmetricKeyWrapper = new JceAsymmetricKeyWrapper(subjectPublicKey);
//		OutputEncryptor encryptor;
//		try {
//		    encryptor = new JceCRMFEncryptorBuilder(PKCSObjectIdentifiers.des_EDE3_CBC).setProvider(ProviderUtils.bcProvider).build();
//		} catch (CRMFException e) {
//		    throw new IllegalStateException(e);
//		}
//		JcaEncryptedValueBuilder jcaEncryptedValueBuilder = new JcaEncryptedValueBuilder(jceAsymmetricKeyWrapper, encryptor);
//		EncryptedValue encryptedCert;
//		try {
//			encryptedCert = jcaEncryptedValueBuilder.build(x509CertificateHolder);
//		} catch (CRMFException e) {
//			throw new IllegalStateException(e);
//		}
//		
//		CertOrEncCert certOrEncCert = new CertOrEncCert(encryptedCert);
//		CertifiedKeyPair certifiedKeyPair = new CertifiedKeyPair(certOrEncCert);
//		PKIStatusInfo status = new PKIStatusInfo(PKIStatus.granted);
//		ASN1OctetString rspInfo = null;
//		CertResponse certResponse = new CertResponse(certReq.getCertReqId(), status, 
//				certifiedKeyPair, rspInfo);
//		certResponses.add(certResponse);
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
//		
		
	}
	public CertificationRequestCertifyActionExecutor withCertTemplate(CertTemplate certTemplate) {
		this.certTemplate = certTemplate;
		return this;
	}
	

}
