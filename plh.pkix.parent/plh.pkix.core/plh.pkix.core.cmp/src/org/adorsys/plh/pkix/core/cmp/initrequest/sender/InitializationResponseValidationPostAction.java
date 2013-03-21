package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.ErrorMessageHelper;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.store.PKISignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.store.ValidationResult;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;

public class InitializationResponseValidationPostAction extends GenericAction {
	public static final String ACCEPT_OUTCOME="accept";

	private ValidationResult validationResult;
	
	private final BuilderChecker checker = new BuilderChecker(InitializationResponseValidationPostAction.class);
	public InitializationResponseValidationPostAction(
			ActionContext actionContext,
			PKISignedMessageValidator signedMessageValidator) {
		super(actionContext);
		checker.checkNull(actionContext,signedMessageValidator);
		
		addProcessor(ACCEPT_OUTCOME, InitializationResponseAcceptActionPreProcessor.class);
		addProcessor(USER_FEEDBACK_OUTCOME, InitializationResponseValidationUserFeedbackProcessor.class);

		PKIMessage responseMessage = actionContext.get1(PKIMessage.class);
		ProtectedPKIMessage protectedPKIMessage = new ProtectedPKIMessage(new GeneralPKIMessage(responseMessage));
		X509CertificateHolder[] certificates2 = protectedPKIMessage.getCertificates();
		X509CertificateHolder senderCertificate = certificates2[0];
		
		try {
			validationResult = signedMessageValidator.getValidationResult(senderCertificate);
			if(!validationResult.isValidSignature() || validationResult.hasError()){
				setOutcome(USER_FEEDBACK_OUTCOME);			
			} else {
				setOutcome(ACCEPT_OUTCOME);
			}
		} catch (SignedMailValidatorException e) {
			CMPRequest cmpRequest = actionContext.get1(CMPRequest.class);
			OutgoingRequests requests = actionContext.get1(OutgoingRequests.class);
			ErrorMessageHelper.processError(cmpRequest, requests, e.getErrorMessage());
		}
	}
}
