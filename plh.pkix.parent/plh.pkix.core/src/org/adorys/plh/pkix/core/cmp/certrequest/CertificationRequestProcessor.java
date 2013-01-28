package org.adorys.plh.pkix.core.cmp.certrequest;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.stores.PendingResponses;
import org.adorys.plh.pkix.core.cmp.utils.KeyIdUtils;
import org.adorys.plh.pkix.core.cmp.utils.OptionalValidityHolder;
import org.adorys.plh.pkix.core.cmp.utils.PublicKeyUtils;
import org.adorys.plh.pkix.core.cmp.utils.ResponseFactory;
import org.adorys.plh.pkix.core.cmp.utils.UUIDUtils;
import org.adorys.plh.pkix.core.cmp.utils.V3CertificateUtils;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.jcajce.JcaEncryptedValueBuilder;
import org.bouncycastle.cert.crmf.jcajce.JceCRMFEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;

public class CertificationRequestProcessor {
	
	/**
	 * End entity controlling this processor
	 */
	private X500Name issuerName;
	private PrivateKey issuerPrivateKey;
	private X509CertificateHolder issuerX509CertificateHolder;
	private byte[] issuerKeyId;
	private PendingResponses pendingResponses;
	
	
	public CertificationRequestProcessor setPendingResponses(PendingResponses pendingResponses) {
		this.pendingResponses = pendingResponses;
		return this;
	}

	public CertificationRequestProcessor setIssuerName(X500Name issuerName) {
		this.issuerName = issuerName;
		return this;
	}

	public CertificationRequestProcessor setIssuerPrivateKey(PrivateKey issuerPrivateKey) {
		this.issuerPrivateKey = issuerPrivateKey;
		return this;
	}

	public CertificationRequestProcessor setIssuerX509CertificateHolder(
			X509CertificateHolder issuerX509CertificateHolder) {
		this.issuerX509CertificateHolder = issuerX509CertificateHolder;
		return this;
	}

	public CertificationRequestProcessor setIssuerKeyId(byte[] issuerKeyId) {
		this.issuerKeyId = issuerKeyId;
		return this;
	}
	private void validate(){
		assert issuerName!=null : "Field issuerName can not be null";
		assert issuerPrivateKey!=null : "Field issuerPrivateKey can not be null";
		assert issuerX509CertificateHolder!=null : "Field issuerX509CertificateHolder can ot be null";
		assert pendingResponses!=null : "Field pendingResponses can ot be null";		
	}
	public HttpResponse process0(GeneralPKIMessage pkiMessage) {
		try {

			validate();
			
			assert pkiMessage!=null : "Field pkiMessage can not be null";
			if(issuerKeyId==null)
				issuerKeyId = KeyIdUtils.getSubjectKeyIdentifierAsByteString(issuerX509CertificateHolder);
			
			Provider provider = PlhCMPSystem.getProvider();
			
			PKIBody pkiBody = pkiMessage.getBody();
			
			PKIHeader pkiHeader = pkiMessage.getHeader();
	
			CertReqMessages certReqMessages = CertReqMessages.getInstance(pkiBody
					.getContent());
			CertReqMsg[] certReqMsgArray = certReqMessages.toCertReqMsgArray();
			List<CertResponse> certResponses = new ArrayList<CertResponse>();
			
			for (CertReqMsg certReqMsg : certReqMsgArray) {
				CertRequest certReq = certReqMsg.getCertReq();
				CertTemplate certTemplate = certReq.getCertTemplate();
				X500Name issuer = certTemplate.getIssuer();
				if(!issuerName.equals(issuer)) continue;

				SubjectPublicKeyInfo subjectPublicKeyInfo = certTemplate.getPublicKey();
				PublicKey subjectPublicKey;
				try {
					subjectPublicKey = PublicKeyUtils.getPublicKey(subjectPublicKeyInfo, provider);
				} catch (Exception e) {
					throw new IllegalStateException(e);
				}

				OptionalValidityHolder optionalValidityHolder = new OptionalValidityHolder(certTemplate.getValidity());
				Time notBefore = optionalValidityHolder.getNotBefore();
				Time notAfter = optionalValidityHolder.getNotAfter();
				
				X509CertificateHolder x509CertificateHolder = generateCertificate(
						certTemplate.getSubject(), notBefore.getDate(), notAfter.getDate(), 
						subjectPublicKey, issuerPrivateKey, issuerX509CertificateHolder);

				JceAsymmetricKeyWrapper jceAsymmetricKeyWrapper = new JceAsymmetricKeyWrapper(subjectPublicKey);
				OutputEncryptor encryptor;
				try {
				    encryptor = new JceCRMFEncryptorBuilder(PKCSObjectIdentifiers.des_EDE3_CBC).setProvider(provider).build();
				} catch (CRMFException e) {
				    throw new IllegalStateException(e);
				}
				JcaEncryptedValueBuilder jcaEncryptedValueBuilder = new JcaEncryptedValueBuilder(jceAsymmetricKeyWrapper, encryptor);
				EncryptedValue encryptedCert;
				try {
					encryptedCert = jcaEncryptedValueBuilder.build(x509CertificateHolder);
				} catch (CRMFException e) {
					throw new IllegalStateException(e);
				}
				
				CertOrEncCert certOrEncCert = new CertOrEncCert(encryptedCert);
				CertifiedKeyPair certifiedKeyPair = new CertifiedKeyPair(certOrEncCert);
				PKIStatusInfo status = new PKIStatusInfo(PKIStatus.granted);
				ASN1OctetString rspInfo = null;
				CertResponse certResponse = new CertResponse(certReq.getCertReqId(), status, 
						certifiedKeyPair, rspInfo);
				certResponses.add(certResponse);
			}
	
			CMPCertificate[] caPubs = new CMPCertificate[]{new CMPCertificate(issuerX509CertificateHolder.toASN1Structure())};
			CertResponse[] response = certResponses.toArray(new CertResponse[certResponses.size()]);
			CertRepMessage certRepMessage = new CertRepMessage(caPubs, response);
			
			GeneralName certificateRecipient = pkiHeader.getSender();
			GeneralName certificateSender = new GeneralName(issuerName);
	
			ProtectedPKIMessage mainMessage;
			
			ProtectedPKIMessageBuilder protectedPKIMessageBuilder = new ProtectedPKIMessageBuilder(certificateSender, certificateRecipient)
					.setBody(new PKIBody(PKIBody.TYPE_CERT_REP, certRepMessage))
					.addCMPCertificate(issuerX509CertificateHolder)
					.setMessageTime(new Date())
					.setSenderKID(issuerKeyId)
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
	
			ContentSigner senderSigner;
			try {
				senderSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(provider).build(issuerPrivateKey);
			} catch (OperatorCreationException e) {
				throw new IllegalStateException(e);
			}
	
			try {
				mainMessage = protectedPKIMessageBuilder.build(senderSigner);
				PKIMessage responseMessage = mainMessage.toASN1Structure();
				pendingResponses.add(responseMessage);
				return ResponseFactory.create(HttpStatus.SC_OK, null);
			} catch (CMPException e) {
				throw new IllegalStateException(e);
			}
		} finally {
			end();
		}
	}

	private void end() {
		issuerName=null;
		issuerPrivateKey=null;
		issuerX509CertificateHolder=null;
		pendingResponses=null;
		issuerKeyId=null;
	}
	
	public static final X509CertificateHolder generateCertificate(X500Name subject, 
			Date notBefore, Date notAfter, 
			PublicKey subjectPublicKey,
			PrivateKey issuerPrivateKey, X509CertificateHolder issuerX509CertificateHolder){
		return V3CertificateUtils.makeV3Certificate(subjectPublicKey, subject, 
				issuerPrivateKey, issuerX509CertificateHolder, notBefore, notAfter, PlhCMPSystem.getProvider());
	}
}
