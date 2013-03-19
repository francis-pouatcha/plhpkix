package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import java.util.Arrays;

import org.adorsys.plh.pkix.core.cmp.message.CertificateValidatingProcessingResult;
import org.adorsys.plh.pkix.core.cmp.message.PkiMessageChecker;
import org.adorsys.plh.pkix.core.cmp.registration.RegistrationRequestSendActionProcessor;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.ErrorMessageHelper;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.smime.contact.ContactManagerImpl;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.i18n.ErrorBundle;

public class InitializationResponseValidationActionProcessor implements ActionProcessor{

	BuilderChecker checker = new BuilderChecker(InitializationResponseValidationActionProcessor.class);
	public void process(ActionContext actionContext) {
		checker.checkNull(actionContext);
		
		PKIMessage responseMessage = actionContext.get1(PKIMessage.class);
		ContactManager contactManager = actionContext.get1(ContactManagerImpl.class);
		OutgoingRequests requests = actionContext.get1(OutgoingRequests.class);
		checker.checkNull(responseMessage,requests, contactManager);

		// store the incoming response
		CMPRequest cmpRequest = requests.loadRequest(responseMessage.getHeader().getTransactionID());
		if(cmpRequest==null){
			// non existing request can not be processed. Ignore.
			return;// no send back
		}
			
		cmpRequest.setResponseMessage(responseMessage);
		actionContext.put(CMPRequest.class, cmpRequest);
		try {
			CertificateValidatingProcessingResult<ProtectedPKIMessage> pr
			= new PkiMessageChecker().check(responseMessage,contactManager);
			ActionHandler actionHandler = actionContext.get1(ActionHandler.class,null);
			// Validate Results
			Action postAction = new InitializationResponseValidationPostAction(actionContext, pr);
			actionHandler.handle(Arrays.asList(postAction));
		} catch(PlhUncheckedException e){
			ErrorMessageHelper.processError(cmpRequest, requests, e.getErrorMessage());
		} catch (RuntimeException r){
			ErrorBundle errorMessage = PlhUncheckedException.toErrorMessage(r, RegistrationRequestSendActionProcessor.class.getName()+"#process");
			ErrorMessageHelper.processError(cmpRequest, requests, errorMessage);
		}
	}
}
