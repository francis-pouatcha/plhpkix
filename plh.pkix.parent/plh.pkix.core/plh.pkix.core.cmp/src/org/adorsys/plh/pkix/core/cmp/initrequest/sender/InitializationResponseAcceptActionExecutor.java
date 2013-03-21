package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import java.security.cert.PKIXParameters;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.initrequest.InitRequestMessages;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.smime.contact.ContactManagerImpl;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.jca.PKIXParametersFactory;
import org.adorsys.plh.pkix.core.utils.store.CertAndCertPath;
import org.adorsys.plh.pkix.core.utils.store.CertPathAndOrigin;
import org.adorsys.plh.pkix.core.utils.store.GeneralCertValidator;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;

/**
 * Processes a initialization response.
 * 
 * According to the CMP Specification, each initialization reply might group responses of
 * one or more certification requests. But this framework assumes each certification request 
 * will be replied into a proper CMP message. This limits the extent of the CMP specification
 * for the sake of simplicity.
 * 
 * We instead use the List of Responses to map the transmission of the certificate chain 
 * associated with the issued certificate. The first response will carry the requested certificate.
 * The next one the ca certificate used to signed that certificate and the last one carrying a
 * root certificate.
 * 
 * From the actionContext, following information are required:
 * <ul>
 * 		<li>PKIMessageActionData. This carries the message being processed. 
 * 				Default entry of {@link PKIMessageActionData}</li>
 * </ul>
 * 
 * The result of the execute method is the certificate chain sent by the registration
 * authority.
 * 
 * @author francis
 *
 */
public class InitializationResponseAcceptActionExecutor {

	private static final String RESOURCE_NAME = InitRequestMessages.class.getName();

	private ActionContext actionContext;
	
	private final BuilderChecker checker = new BuilderChecker(
			InitializationResponseAcceptActionExecutor.class);
	
	public List<ProcessingResults<CertAndCertPath>> execute() {

		checker.checkDirty().checkNull(actionContext);
		CMPRequest cmpRequest = actionContext.get1(CMPRequest.class);
		ContactManager contactManager = actionContext.get1(ContactManagerImpl.class);
		checker.checkDirty().checkNull(cmpRequest, contactManager);
		
		CertReqMessages certReqMessages = CertReqMessages
				.getInstance(cmpRequest.getPkiMessage().getBody().getContent());
		CertReqMsg[] certReqMsgArray = certReqMessages.toCertReqMsgArray();
		if(certReqMsgArray==null || certReqMsgArray.length<=0)
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					InitRequestMessages.InitRequestMessages_request_noCertrequestMessageInHolder);

		if(certReqMsgArray.length>1)
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					InitRequestMessages.InitRequestMessages_request_processOnlyFirstcertRequestMessage);
		
		CertReqMsg certReqMsg = certReqMsgArray[0];
		ASN1Integer certReqId=certReqMsg.getCertReq().getCertReqId();
		// the original template
		CertTemplate certTemplate = certReqMsg.getCertReq().getCertTemplate();
		
		PKIMessage responseMessage = cmpRequest.getResponseMessage();
		CertRepMessage certRepMessage = CertRepMessage.getInstance(responseMessage.getBody().getContent());

		// check that sender is the addressed CA
		CertResponse[] response = certRepMessage.getResponse();
		if(response.length<=0)
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					InitRequestMessages.InitRequestMessages_response_certResponseEmpty);

		CMPCertificate[] caPubs = certRepMessage.getCaPubs();
		// put all certificate including caPubs in this array
		List<X509CertificateHolder> caCertificates = new ArrayList<X509CertificateHolder>();
		for (CMPCertificate cmpCertificate : caPubs) {
			caCertificates.add(new X509CertificateHolder(cmpCertificate.getX509v3PKCert()));
		}
		
		// iterate through the cert response and build the certification path.
		List<X509CertificateHolder> requestedCerts = new ArrayList<X509CertificateHolder>();
		for (int i = 0; i < response.length; i++) {
			CertResponse certResponse = response[i];
			ASN1Integer crid = certResponse.getCertReqId();
			
			if(crid == null)// : "Missing cert request id, do not process";
				throw PlhUncheckedException.toException(RESOURCE_NAME,
						InitRequestMessages.InitRequestMessages_response_missingCertRequestId);
			
			if(!certReqId.equals(crid))
				throw PlhUncheckedException.toException(RESOURCE_NAME,
						InitRequestMessages.InitRequestMessages_response_wrongCertRequestId,
						new Object[]{KeyIdUtils.hexEncode(crid),
						KeyIdUtils.hexEncode(certReqId),
						KeyIdUtils.hexEncode(cmpRequest.getTransactionID())});
			
			CertOrEncCert certOrEncCert = certResponse
					.getCertifiedKeyPair().getCertOrEncCert();
			CMPCertificate cmpCertificate = certOrEncCert.getCertificate();
			requestedCerts.add(new X509CertificateHolder(cmpCertificate.getX509v3PKCert()));
		}

		List<X509CertificateHolder> allCertificates = new ArrayList<X509CertificateHolder>(requestedCerts);
		allCertificates.addAll(caCertificates);
		PKIXParameters params = PKIXParametersFactory.makeParams(
				contactManager.getTrustAnchors(),
				contactManager.getCrl(),
				contactManager.findCertStores(allCertificates));
		
		List<ProcessingResults<CertAndCertPath>> certValidationResults = new ArrayList<ProcessingResults<CertAndCertPath>>(requestedCerts.size());
		for (X509CertificateHolder x509CertificateHolder : requestedCerts) {
			ProcessingResults<CertAndCertPath> processingResults = new ProcessingResults<CertAndCertPath>();
			GeneralCertValidator generalCertValidator;
			try {
				generalCertValidator = new GeneralCertValidator()
					.withPKIXParameters(params)
					.withSenderSupliedCerts(V3CertificateUtils.createCertStore(allCertificates))
					.validate(new Date());
				CertPathAndOrigin certPathAndOrigin = generalCertValidator.getCertPathAndOrigin();
				processingResults.setReturnValue(new CertAndCertPath(x509CertificateHolder, certPathAndOrigin));
				processingResults.addErrors(generalCertValidator.getErrors());
				processingResults.addNotifications(generalCertValidator.getNotifications());
				new InitializationReplyValidator()
					.withCertTemplate(certTemplate)
					.validate(processingResults);
			} catch (SignedMailValidatorException e) {
				processingResults.addError(e.getErrorMessage());
			}
			certValidationResults.add(processingResults);
		}

		return certValidationResults;
	}

	public InitializationResponseAcceptActionExecutor withActionContext(ActionContext actionContext) {
		this.actionContext = actionContext;
		return this;
	}
}
