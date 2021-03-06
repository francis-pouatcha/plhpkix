package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.math.BigInteger;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.certrequest.CertRequestMessages;
import org.adorsys.plh.pkix.core.cmp.message.PKIMessageActionData;
import org.adorsys.plh.pkix.core.cmp.stores.PendingRequest;
import org.adorsys.plh.pkix.core.cmp.stores.PendingRequestData;
import org.adorsys.plh.pkix.core.cmp.stores.PendingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.EncryptedValueParser;
import org.bouncycastle.cert.crmf.ValueDecryptorGenerator;
import org.bouncycastle.cert.crmf.jcajce.JceAsymmetricValueDecryptorGenerator;
import org.bouncycastle.i18n.ErrorBundle;

/**
 * Processes a certification reply.
 * 
 * According to the CMP Specification, each certification reply might group responses of
 * one or more certification requests. But this framework assumes each certification request 
 * will be replied into a proper CMP message. This limits the extent of the CMP specification
 * for the sake of simplicity.
 * 
 * We instead use the List of Responses to map the transmission of the certificate chain 
 * associated with the issued certificate. The first response will carry the issued certificate.
 * The next one the ca certificate used to signed that certificate and the last one carrying a
 * root certificate.
 * 
 * From the actionContext, following information are required:
 * <ul>
 * 		<li>PKIMessageActionData. This carries the message being processed. 
 * 				Default entry of {@link PKIMessageActionData}</li>
 * 		<li>PrivateKeyEntry. PrivateKey entry associated with the certificate being 
 * 				issued. Keyed with the subjectKeyIdentifier of the associated
 * 				public key.</li>
 * </ul>
 * 
 * The result of the execute method is the certificate chain sent by the certification
 * authority.
 * 
 * @author francis
 *
 */
public class CertificationReplyAcceptActionExecutor {

	private static final String RESOURCE_NAME = CertRequestMessages.class
			.getName();

	private ActionContext actionContext;
	
	private final BuilderChecker checker = new BuilderChecker(
			CertificationReplyAcceptActionExecutor.class);
	
	public ProcessingResults<List<X509CertificateHolder>> execute() {

		checker.checkDirty().checkNull(actionContext);

		PKIMessageActionData actionData =  actionContext.get(PKIMessageActionData.class,null);
		GeneralPKIMessage generalPKIMessage = new GeneralPKIMessage(actionData.getPkiMessage());
		PKIBody pkiBody = generalPKIMessage.getBody();
		CertRepMessage certRepMessage = CertRepMessage.getInstance(pkiBody.getContent());

		ProcessingResults<List<X509CertificateHolder>> pr = new ProcessingResults<List<X509CertificateHolder>>();

		// check that sender is the addressed CA
		CertResponse[] response = certRepMessage.getResponse();
		if(response.length<=0){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CertRequestMessages.response.certResponseEmpty");
			pr.addError(msg);
			return pr;
		}
		BigInteger certReqIdAsBigInteger=null;
		ASN1Integer certReqId=null;
		CertResponse certResp = response[0];

		ASN1Integer crid = certResp.getCertReqId();
		if(crid == null){// : "Missing cert request id, do not process";
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CertRequestMessages.response.missingCertRequestId");
			pr.addError(msg);
			return pr;
		}
		
		certReqIdAsBigInteger = crid.getPositiveValue();
		certReqId = crid;
		
		PendingRequests pendingRequests = actionContext.get(PendingRequests.class, null);
		PendingRequestData pendingRequestData = pendingRequests.loadPendingRequest(certReqId.getPositiveValue());
		if(pendingRequestData==null){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CertRequestMessages.request.missingCertRequestHolder");
			pr.addError(msg);
			return pr;
		}

		// verify that certificate meet initial requirements.
		PendingRequest pendingRequest = pendingRequestData.getPendingRequest();
		CertReqMessages certReqMessages = CertReqMessages
				.getInstance(pendingRequest.getPkiMessage().getBody()
						.getContent());
		CertReqMsg[] certReqMsgArray = certReqMessages.toCertReqMsgArray();
		if(certReqMsgArray==null || certReqMsgArray.length<=0){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CertRequestMessages.request.noCertrequestMessageInHolder");
			pr.addError(msg);
			return pr;
		}

		if(certReqMsgArray.length>1){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CertRequestMessages.request.processOnlyFirstcertRequestMessage");
			pr.addNotification(msg);
		}
		CertReqMsg certReqMsg = certReqMsgArray[0];

		CertTemplate certTemplate = certReqMsg.getCertReq()
				.getCertTemplate();
		SubjectPublicKeyInfo publicKeyInfo = certTemplate.getPublicKey();
		KeyStoreWraper keyStoreWraper = actionContext.get(KeyStoreWraper.class);
		PrivateKeyEntry privateKeyEntry = keyStoreWraper.findPrivateKeyEntryByPublicKeyInfo(publicKeyInfo);
		if(privateKeyEntry==null){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CertRequestMessages.request.missingAssociatedPoP");
			pr.addError(msg);
			return pr;
		}

		// iterate through the cert response and build the certification path.
		List<X509CertificateHolder> certificateChain = new ArrayList<X509CertificateHolder>(response.length);
		for (CertResponse certResponse : response) {
			if(!certReqIdAsBigInteger.equals(crid.getPositiveValue())){
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						"CertRequestMessages.response.allResponsesMussCarrySameCertReqId");
				pr.addError(msg);
				return pr;
			}
			
			try {
				X509CertificateHolder certificate = readCertificate(certResponse, privateKeyEntry.getPrivateKey());
				certificateChain.add(certificate);
			} catch (CRMFException e) {
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						"CertRequestMessages.request.canNotDecryptCertificate");
				pr.addError(msg);
				return pr;
			}
		}			
		// the first certificate
		if(!pr.hasReturnValue())pr.setReturnValue(certificateChain);
								
		new CertificationReplyValidator()
			.withCertTemplate(certTemplate)
			.validate(pr);
		return pr;
	}

	public CertificationReplyAcceptActionExecutor withActionContext(ActionContext actionContext) {
		this.actionContext = actionContext;
		return this;
	}

	private X509CertificateHolder readCertificate(CertResponse certResponse, PrivateKey subjectPrivateKey) throws CRMFException{
		CertOrEncCert certOrEncCert = certResponse
				.getCertifiedKeyPair().getCertOrEncCert();
		EncryptedValue encryptedCert = certOrEncCert.getEncryptedCert();

		ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(
				subjectPrivateKey).setProvider(ProviderUtils.bcProvider);
		EncryptedValueParser parser = new EncryptedValueParser(
				encryptedCert);
		return parser.readCertificateHolder(decGen);
	}
}
