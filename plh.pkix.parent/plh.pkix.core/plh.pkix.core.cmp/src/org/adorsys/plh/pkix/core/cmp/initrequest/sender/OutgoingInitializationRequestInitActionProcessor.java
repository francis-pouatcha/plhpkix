package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.Arrays;
import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.registration.RegistrationRequestInitPostAction;
import org.adorsys.plh.pkix.core.cmp.registration.RegistrationRequestSendActionProcessor;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1ProcessingResult;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.i18n.ErrorBundle;

/**
 * Builds a registration request
 * 
 * @author francis
 *
 */
public class OutgoingInitializationRequestInitActionProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(OutgoingInitializationRequestInitActionProcessor.class);
	@Override
	public void process(ActionContext context) {
		OutgoingRequests initializationRequests = context.get1(OutgoingRequests.class);
		ActionHandler actionHandler = context.get1(ActionHandler.class);
		ContactManager contactManager = context.get1(ContactManager.class);
		InitializationRequestFieldHolder f = context.get1(InitializationRequestFieldHolder.class);
		
		checker.checkNull(contactManager,initializationRequests,actionHandler);
			
		ProcessingResults<CMPRequest> results = null;
		try {
			OutgoingInitializationRequestInitActionExecutor builder = new OutgoingInitializationRequestInitActionExecutor()
					.withCertAuthorityName(f.getCertAuthorityName())
					.withNotAfter(f.getNotAfter())
					.withNotBefore(f.getNotBefore())
					.withReceiverCertificate(f.getReceiverCertificate())
					.withReceiverEmail(f.getReceiverEmail())
					.withSubjectAltNames(f.getSubjectAltNames())
					.withSubjectDN(f.getSubjectDN())
					.withSubjectPublicKeyInfo(f.getSubjectPublicKeyInfo());
			if(f.isCaSet())builder = builder.withCa(f.isCa());
			if(f.isKeyUsageSet())builder=builder.withKeyUsage(f.getKeyUsage());
			
			PrivateKeyEntry privateKeyEntry = contactManager.getMainMessagePrivateKeyEntry();
			results = builder.build(privateKeyEntry);
		} catch(PlhUncheckedException e){
			results = new ProcessingResults<CMPRequest>();
			results.addError(e.getErrorMessage());
		} catch (RuntimeException r){
			ErrorBundle errorMessage = PlhUncheckedException.toErrorMessage(r, RegistrationRequestSendActionProcessor.class.getName()+"#process");
			results = new ProcessingResults<CMPRequest>();
			results.addError(errorMessage);
		}
		
		if(!results.hasReturnValue())
			results.setReturnValue(new CMPRequest());
		
		CMPRequest cmpRequest = results.getReturnValue();
		ASN1ProcessingResult processingResult = results.getASN1ProcessingResult();
		if(processingResult!=null){
			cmpRequest.addProcessingResult(processingResult);
		}
		
		ASN1Action nextAction = new ASN1Action(
				cmpRequest.getTransactionID(), 
				new DERGeneralizedTime(new Date()), 
				UUIDUtils.newUUIDasASN1OctetString(), 
				new DERIA5String(OutgoingInitializationRequestInitPostAction.class.getSimpleName()));
		
		cmpRequest.pushNextAction(nextAction);
		initializationRequests.storeRequest(cmpRequest);
		context.put(CMPRequest.class, cmpRequest);
		
		Action postAction = new RegistrationRequestInitPostAction(context);
		actionHandler.handle(Arrays.asList(postAction));
	}
}
