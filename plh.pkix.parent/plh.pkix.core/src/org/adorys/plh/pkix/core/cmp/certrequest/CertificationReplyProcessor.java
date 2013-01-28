package org.adorys.plh.pkix.core.cmp.certrequest;

import java.security.PrivateKey;
import java.security.Provider;
import java.util.ArrayList;
import java.util.List;

import org.adorys.plh.pkix.core.cmp.PendingRequestHolder;
import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.message.PkiMessageChecker;
import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.stores.PendingCertAnn;
import org.adorys.plh.pkix.core.cmp.stores.PendingPollRequest;
import org.adorys.plh.pkix.core.cmp.utils.OptionalValidityComparator;
import org.adorys.plh.pkix.core.cmp.utils.OptionalValidityHolder;
import org.adorys.plh.pkix.core.cmp.utils.ResponseFactory;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.EncryptedValueParser;
import org.bouncycastle.cert.crmf.ValueDecryptorGenerator;
import org.bouncycastle.cert.crmf.jcajce.JceAsymmetricValueDecryptorGenerator;

public class CertificationReplyProcessor {

	private X500Name endEntityName;
	private PrivateKey subjectPrivateKey;
	private CertificateStore certificateStore;
	private PendingPollRequest pendingPollRequest;
	private PendingCertAnn pendingCertAnns;
	public HttpResponse process1(GeneralPKIMessage generalPKIMessage) {
		try {
			validate();
			
			Provider provider = PlhCMPSystem.getProvider();

			new PkiMessageChecker().withCertificateStore(certificateStore).check(
					generalPKIMessage);
			
			PKIBody pkiBody = generalPKIMessage.getBody();
			CertRepMessage certRepMessage = CertRepMessage.getInstance(pkiBody
					.getContent());
			
			// check that sender is the addressed ca
			CertResponse[] response = certRepMessage.getResponse();
			List<X509CertificateHolder> issuedCertificates = new ArrayList<X509CertificateHolder>(
					response.length);
			
			for (CertResponse certResponse : response) {
				ASN1Integer certReqId = certResponse.getCertReqId();
				assert certReqId != null : "Missing cert request id";
				
				PendingRequestHolder pendingRequestHolder = pendingPollRequest
						.loadPollRequestHolder(certReqId);
				assert pendingRequestHolder != null : "Missing cert request holder";
				// verify that certificate meet initial requirements.
				CertReqMessages certReqMessages = CertReqMessages
						.getInstance(pendingRequestHolder.getPkiMessage().getBody()
								.getContent());
				CertReqMsg[] certReqMsgArray = certReqMessages.toCertReqMsgArray();
				for (CertReqMsg certReqMsg : certReqMsgArray) {
					CertTemplate certTemplate = certReqMsg.getCertReq()
							.getCertTemplate();
					CertOrEncCert certOrEncCert = certResponse
							.getCertifiedKeyPair().getCertOrEncCert();
					EncryptedValue encryptedCert = certOrEncCert.getEncryptedCert();
					
					ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(
							subjectPrivateKey).setProvider(provider);
					EncryptedValueParser parser = new EncryptedValueParser(
							encryptedCert);
					X509CertificateHolder issuedCertificate;
					try {
						issuedCertificate = parser.readCertificateHolder(decGen);
					} catch (CRMFException e) {
						return ResponseFactory.create(HttpStatus.SC_BAD_REQUEST,
								e.getMessage());
					}
					
					if (!certTemplate.getSubject().equals(
							issuedCertificate.getSubject()))
						return ResponseFactory.create(HttpStatus.SC_BAD_REQUEST,
								"Subject not matching original request");
					
					// SubjectPublicKeyInfo subjectPublicKeyInfo = ;
					//
					// PublicKey subjectPublicKey;
					// try {
					// subjectPublicKey = PublicKeyUtils.getPublicKey(
					// subjectPublicKeyInfo, provider);
					// } catch (InvalidKeySpecException e) {
					// return ResponseFactory.create(HttpStatus.SC_BAD_REQUEST,
					// e.getMessage());
					// }
					//
					if (!certTemplate.getPublicKey().equals(
							issuedCertificate.getSubjectPublicKeyInfo()))
						return ResponseFactory.create(HttpStatus.SC_BAD_REQUEST,
								"Subject not matching original request");
					
					if (!certTemplate.getIssuer().equals(
							issuedCertificate.getIssuer()))
						return ResponseFactory.create(HttpStatus.SC_BAD_REQUEST,
								"Subject not matching original request");
					
					OptionalValidityHolder optionalValidityFromTemplate = new OptionalValidityHolder(
							certTemplate.getValidity());
					boolean notBeforeCompatible = OptionalValidityComparator
							.isNotBeforeCompatible(optionalValidityFromTemplate
									.getNotBefore().getDate(), issuedCertificate
									.getNotBefore());
					boolean notAfterCompatible = OptionalValidityComparator
							.isNotAfterCompatible(optionalValidityFromTemplate
									.getNotAfter().getDate(), issuedCertificate
									.getNotAfter());
					if (!notBeforeCompatible || !notAfterCompatible)
						return ResponseFactory.create(HttpStatus.SC_BAD_REQUEST,
								"Optional validity not matching");
					
					// Store the certificate
					issuedCertificates.add(issuedCertificate);
				}
			}

			for (X509CertificateHolder issuedCertificate : issuedCertificates) {
				certificateStore.addCertificate(issuedCertificate);
				pendingCertAnns.add(issuedCertificate);
			}
		} finally {
			end();
			
		}

		return ResponseFactory.create(HttpStatus.SC_OK, null);
	}

	public CertificationReplyProcessor withEndEntityName(X500Name endEntityName) {
		this.endEntityName = endEntityName;
		return this;
	}

	public CertificationReplyProcessor withSubjectPrivateKey(
			PrivateKey subjectPrivateKey) {
		this.subjectPrivateKey = subjectPrivateKey;
		return this;
	}

	public CertificationReplyProcessor withCertificateStore(CertificateStore certificateStore) {
		this.certificateStore = certificateStore;
		return this;
	}

	public CertificationReplyProcessor withPendingPollRequest(PendingPollRequest pendingPollRequest) {
		this.pendingPollRequest = pendingPollRequest;
		return this;
	}

	public CertificationReplyProcessor withPendingCertAnns(PendingCertAnn pendingCertAnns) {
		this.pendingCertAnns = pendingCertAnns;
		return this;
	}

	private void validate() {
		assert this.endEntityName != null : "Field endEntityName can not be null";
		assert this.subjectPrivateKey != null : "Field subjectPrivateKey can not be null";
		assert this.certificateStore != null : "Field certificateStore can not be null";
		assert this.pendingPollRequest != null : "Field pendingCertRequest can not be null";
		assert this.pendingCertAnns != null : "Field pendingCertAnns can not be null";
	}

	private void end() {
		this.endEntityName = null;
		this.subjectPrivateKey = null;
		this.certificateStore = null;
		this.pendingPollRequest = null;
		this.pendingCertAnns = null;
	}
}
