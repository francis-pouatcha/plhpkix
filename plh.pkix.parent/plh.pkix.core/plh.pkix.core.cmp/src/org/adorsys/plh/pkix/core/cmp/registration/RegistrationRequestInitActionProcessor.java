package org.adorsys.plh.pkix.core.cmp.registration;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.Arrays;
import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1ProcessingResult;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;

/**
 * Builds a registration request
 * 
 * @author francis
 *
 */
public class RegistrationRequestInitActionProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(RegistrationRequestInitActionProcessor.class);
	@Override
	public void process(ActionContext context) {
		CMPRequests requestOut = context.get1(CMPRequests.class);
		ActionHandler actionHandler = context.get1(ActionHandler.class);
		checker.checkNull(requestOut,actionHandler);

		// The private key entry to be registered.
		PrivateKeyEntry keyToRegister = context.get1(PrivateKeyEntry.class);
		checker.checkNull(keyToRegister);
		
		// create and store the request.
		ProcessingResults<CMPRequest> processingResults = new RegistrationRequestInitActionExecutor().build(keyToRegister);
		CMPRequest cmpRequest = processingResults.getReturnValue();
		if(cmpRequest==null)cmpRequest=new CMPRequest();
		
		ASN1ProcessingResult processingResult = processingResults.getASN1ProcessingResult();
		if(processingResult!=null){
			cmpRequest.addProcessingResult(processingResult);
		}
		
		ASN1Action nextAction = new ASN1Action(
				cmpRequest.getTransactionID(), 
				new DERGeneralizedTime(new Date()), 
				UUIDUtils.newUUIDasASN1OctetString(), 
				new DERIA5String(RegistrationRequestInitPostAction.class.getSimpleName()));
		
		cmpRequest.pushNextAction(nextAction);
		requestOut.storeRequest(cmpRequest);
		context.put(CMPRequest.class, cmpRequest);
		
		Action postAction = new RegistrationRequestInitPostAction(context);
		actionHandler.handle(Arrays.asList(postAction));
	}
}
