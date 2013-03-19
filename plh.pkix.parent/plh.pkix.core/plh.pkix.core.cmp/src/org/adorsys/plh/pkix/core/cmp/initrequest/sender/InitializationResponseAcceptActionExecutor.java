package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import java.io.IOException;
import java.security.cert.CertStore;
import java.security.cert.PKIXParameters;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.initrequest.InitRequestMessages;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertChainValidationResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertChainValidationResults;
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
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.i18n.ErrorBundle;

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
	
	public ProcessingResults<ASN1CertChainValidationResult> execute() {

		checker.checkDirty().checkNull(actionContext);
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		checker.checkDirty().checkNull(cmpRequest);
		ProcessingResults<ASN1CertChainValidationResult> pr = 
				new ProcessingResults<ASN1CertChainValidationResult>();
		
		CertReqMessages certReqMessages = CertReqMessages
				.getInstance(cmpRequest.getPkiMessage().getBody().getContent());
		CertReqMsg[] certReqMsgArray = certReqMessages.toCertReqMsgArray();
		if(certReqMsgArray==null || certReqMsgArray.length<=0){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					InitRequestMessages.InitRequestMessages_request_noCertrequestMessageInHolder);
			pr.addError(msg);
			return pr;
		}

		if(certReqMsgArray.length>1){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					InitRequestMessages.InitRequestMessages_request_processOnlyFirstcertRequestMessage);
			pr.addNotification(msg);
		}
		CertReqMsg certReqMsg = certReqMsgArray[0];
		ASN1Integer certReqId=certReqMsg.getCertReq().getCertReqId();
		// the original template
		CertTemplate certTemplate = certReqMsg.getCertReq().getCertTemplate();
		
		PKIMessage responseMessage = cmpRequest.getResponseMessage();
		CertRepMessage certRepMessage = CertRepMessage.getInstance(responseMessage.getBody().getContent());
		CMPCertificate[] caPubs = certRepMessage.getCaPubs();
		JcaCertStoreBuilder storeBuilder = new JcaCertStoreBuilder()
			.setProvider(ProviderUtils.bcProvider);
		for (CMPCertificate cmpCertificate : caPubs) {
			X509CertificateHolder certificateHolder = new X509CertificateHolder(cmpCertificate.getX509v3PKCert());
			storeBuilder.addCertificate(certificateHolder);
		}
		CertStore senderSupliedCerts = storeBuilder.build();
		PKIXParameters pkixParam = new PKIXParameters(trustAnchors);
			
		// check that sender is the addressed CA
		CertResponse[] response = certRepMessage.getResponse();
		if(response.length<=0){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					InitRequestMessages.InitRequestMessages_response_certResponseEmpty);
			pr.addError(msg);
			return pr;
		}
		
		// iterate through the cert response and build the certification path.
		for (int i = 0; i < response.length; i++) {
			CertResponse certResponse = response[i];
			ASN1Integer crid = certResponse.getCertReqId();
			if(crid == null){// : "Missing cert request id, do not process";
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						InitRequestMessages.InitRequestMessages_response_missingCertRequestId);
				pr.addError(msg);
				return pr;
			}
			
			if(certReqId.equals(crid)){
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						InitRequestMessages.InitRequestMessages_response_wrongCertRequestId,
						new Object[]{KeyIdUtils.hexEncode(crid),
						KeyIdUtils.hexEncode(certReqId),
						KeyIdUtils.hexEncode(cmpRequest.getTransactionID())});
				pr.addError(msg);
				return pr;
			}

			try {
				CertOrEncCert certOrEncCert = certResponse
						.getCertifiedKeyPair().getCertOrEncCert();
				CMPCertificate cmpCertificate = certOrEncCert.getCertificate();
				new GeneralCertValidator()
					.withPKIXParameters(pkixParam)
					.withSenderSupliedCerts(senderSupliedCerts)
					.validate();
			} catch (IOException e) {
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						"InitRequestMessages.response.canNotReadCertificate");
				pr.addError(msg);
				return pr;
			}
		}

		ASN1CertChainValidationResult certChainValidationResult = new ASN1CertChainValidationResult(cmpRequest.getTransactionID(), certificates);
		new InitializationReplyValidator()
			.withCertTemplate(certTemplate)
			.validate(processingResults);
		
		// the first certificate
		List<List<X509CertificateHolder>> certChains = V3CertificateUtils.splitCertList(certificateChain);
		for (List<X509CertificateHolder> list : certChains) {
			ProcessingResults<List<X509CertificateHolder>> processingResults = new ProcessingResults<List<X509CertificateHolder>>();
			processingResults.setReturnValue(list);
		}
		if(!pr.hasReturnValue())pr.setReturnValue(certChains);
								
		new InitializationReplyValidator()
			.withCertTemplate(certTemplate)
			.validate(pr);
		return pr;
	}

	public InitializationResponseAcceptActionExecutor withActionContext(ActionContext actionContext) {
		this.actionContext = actionContext;
		return this;
	}
}
