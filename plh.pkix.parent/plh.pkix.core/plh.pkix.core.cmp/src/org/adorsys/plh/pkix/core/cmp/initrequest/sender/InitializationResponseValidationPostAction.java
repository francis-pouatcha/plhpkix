package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import java.util.List;

import org.adorsys.plh.pkix.core.cmp.message.CMPMessageValidatorMessages;
import org.adorsys.plh.pkix.core.cmp.message.CertificateValidatingProcessingResult;
import org.adorsys.plh.pkix.core.cmp.message.DeleteMessageActionProcessor;
import org.adorsys.plh.pkix.core.cmp.message.ProcessMessageAfterConfirmActionPreProcessor;
import org.adorsys.plh.pkix.core.cmp.message.RejectMessageAfterConfirmActionPreProcessor;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.GenericAction;
import org.adorsys.plh.pkix.core.utils.action.NullActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.PKISignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.store.PlhPkixCoreMessages;
import org.adorsys.plh.pkix.core.utils.store.ValidationResult;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;

public class InitializationResponseValidationPostAction extends GenericAction {
	public static final String ACCEPT_OUTCOME="accept";

	private CertificateValidatingProcessingResult<ProtectedPKIMessage> processingResults;
	
	private final BuilderChecker checker = new BuilderChecker(InitializationResponseValidationPostAction.class);
	public InitializationResponseValidationPostAction(
			ActionContext actionContext,
			CertificateValidatingProcessingResult<ProtectedPKIMessage> processingResults) {
		super(actionContext);
		checker.checkNull(actionContext,processingResults);
		
		addProcessor(ACCEPT_OUTCOME, InitializationResponseAcceptActionPreProcessor.class);
		addProcessor(CANCEL_OUTCOME, NullActionProcessor.class);
		addProcessor(DELETE_OUTCOME, DeleteMessageActionProcessor.class);
		addProcessor(REJECT_AFTER_CONFIRM_OUTCOME, RejectMessageAfterConfirmActionPreProcessor.class);
		addProcessor(PROCESS_AFTER_CONFIRM_OUTCOME, ProcessMessageAfterConfirmActionPreProcessor.class);
		this.processingResults = processingResults;
		
		if(processingResults.hasError()){
			List<ErrorBundle> errors = processingResults.getErrors();
			if(errors.contains(CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_macProtectionNotSupported))
				setOutcome(DELETE_OUTCOME);
			if(errors.contains(CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_missingProtection))
				setOutcome(DELETE_OUTCOME);
			if(errors.contains(CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_missingRecipient))
				setOutcome(DELETE_OUTCOME);
			if(errors.contains(CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_missingSender))
				setOutcome(DELETE_OUTCOME);
			if(errors.contains(CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_senderNotADirectoryName))
				setOutcome(DELETE_OUTCOME);
			// this will forward to validation. We might have the sender certificate in our store
//			if(errors.contains(CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_notCertificateSentWithMessage))
//				setOutcome(PROCESS_AFTER_CONFIRM_OUTCOME);

			if(errors.contains(CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_senderNotADirectoryName))
				setOutcome(REJECT_OUTCOME);
			
			ProtectedPKIMessage protectedPKIMessage = processingResults.getReturnValue();
			X509CertificateHolder[] certificates = protectedPKIMessage.getCertificates();
			X509CertificateHolder senderCertificate = certificates[0];
			PKISignedMessageValidator validator = processingResults.getValidator();
			ValidationResult validationResult;
			try {
				validationResult = validator.getValidationResult(senderCertificate);
			} catch (SignedMailValidatorException e) {
				setOutcome(DELETE_OUTCOME);				
				return;
			}
			
			// certificate validation
			errors = validationResult.getErrors();
			// Certificate is not in synch with the time of use.
			// Show user and promp user for decision.
			if(errors.contains(PlhPkixCoreMessages.SignatureValidator_certExpired))
				setOutcome(PROCESS_AFTER_CONFIRM_OUTCOME);
			if(errors.contains(PlhPkixCoreMessages.SignatureValidator_certNotYetValid))
				setOutcome(PROCESS_AFTER_CONFIRM_OUTCOME);
			
			// Show user the certificate path for decision
			if(errors.contains(PlhPkixCoreMessages.SignatureValidator_certPathInvalid))
				setOutcome(PROCESS_AFTER_CONFIRM_OUTCOME);
			
			// Show user for decision
			if(errors.contains(PlhPkixCoreMessages.SignatureValidator_signingNotPermitted))
				setOutcome(PROCESS_AFTER_CONFIRM_OUTCOME);
			if(errors.contains(PlhPkixCoreMessages.SignatureValidator_extKeyUsageNotPermitted))
				setOutcome(PROCESS_AFTER_CONFIRM_OUTCOME);
			
			// Discard the message and eventually log error for administration
			if(errors.contains(PlhPkixCoreMessages.SignatureValidator_exceptionRetrievingSignerCert))
				setOutcome(DELETE_OUTCOME);				
			if(errors.contains(PlhPkixCoreMessages.SignatureValidator_exceptionVerifyingSignature))
				setOutcome(DELETE_OUTCOME);				
			if(errors.contains(PlhPkixCoreMessages.SignatureValidator_extKeyUsageError))
				setOutcome(DELETE_OUTCOME);
			if(errors.contains(PlhPkixCoreMessages.SignatureValidator_noSignerCert))
				setOutcome(DELETE_OUTCOME);
			if(errors.contains(PlhPkixCoreMessages.SignatureValidator_noSigningTime))
				setOutcome(DELETE_OUTCOME);
			if(errors.contains(PlhPkixCoreMessages.SignatureValidator_wrongSigner))
				setOutcome(DELETE_OUTCOME);
			if(errors.contains(PlhPkixCoreMessages.SignatureValidator_signatureNotVerified))
				setOutcome(DELETE_OUTCOME);
			
			// Warnings. Will be ignore for now
			if(errors.contains(PlhPkixCoreMessages.SignatureValidator_longValidity));
			if(errors.contains(PlhPkixCoreMessages.SignatureValidator_shortSigningKey));

			
			
			boolean conformityError = false;
			boolean containsCertificateError = false;
			for (ErrorBundle errorBundle : errors) {
				if(errorBundle.getId().contains(".conformity.")){
					conformityError = true;
				} else if(errorBundle.getId().contains(".certificate.")){
					containsCertificateError = true;
				}
			}
			if(conformityError){
				// if the pending message had sent back an error already, confirm and delete message
				// creates a delete or send back message and give to the handler.
				setOutcome(REJECT_AFTER_CONFIRM_OUTCOME);
			} else if(containsCertificateError){
				setOutcome(PROCESS_AFTER_CONFIRM_OUTCOME);
			} else{
				// if the pending message had sent back an error already, confirm and delete message
				// creates a delete or send back message and give to the handler.
				setOutcome(REJECT_AFTER_CONFIRM_OUTCOME);
			}
		} else if(processingResults.hasReturnValue()){
			setOutcome(ACCEPT_OUTCOME);
		} else {
			setOutcome(DELETE_AFTER_CONFIRM_OUTCOME);
		}
	}
	public CertificateValidatingProcessingResult<ProtectedPKIMessage> getProcessingResults() {
		return processingResults;
	}
}
