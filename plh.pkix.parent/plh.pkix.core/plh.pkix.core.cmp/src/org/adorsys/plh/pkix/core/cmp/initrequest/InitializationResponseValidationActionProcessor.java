package org.adorsys.plh.pkix.core.cmp.initrequest;

import java.util.ArrayList;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.message.CertificateValidatingProcessingResult;
import org.adorsys.plh.pkix.core.cmp.message.PKIMessageActionData;
import org.adorsys.plh.pkix.core.cmp.message.PkiMessageChecker;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;

public class InitializationResponseValidationActionProcessor implements ActionProcessor{

	BuilderChecker checker = new BuilderChecker(InitializationResponseValidationActionProcessor.class);
	public void process(ActionContext actionContext) {
		checker.checkDirty().checkNull(actionContext);
		
		PKIMessageActionData messageActionData = actionContext.get(PKIMessageActionData.class);
		KeyStoreWraper keyStoreWraper = actionContext.get(KeyStoreWraper.class);
		ActionHandler actionHandler = actionContext.get(ActionHandler.class,null);
		checker.checkNull(keyStoreWraper,messageActionData,actionHandler);
		
		CertificateValidatingProcessingResult<ProtectedPKIMessage> 
		processingResults = new PkiMessageChecker()
			.withKeyStoreWraper(keyStoreWraper)
			.check(messageActionData.getPkiMessage());

		// Validate Results
		InitializationResponseValidationPostAction postAction = new InitializationResponseValidationPostAction(actionContext, processingResults);
		List<Action> actions = new ArrayList<Action>();
		actions.add(postAction);
		actionHandler.handle(actions);

//		
//		// The requested certificate
//		CertTemplateActionData certTemplateActionData = feedbackContext.get(CertTemplateActionData.class);
//		CertTemplate certTemplate = certTemplateActionData.getCertTemplate();
//
//		// the response
//		GeneralPKIMessageActionData generalPKIMessageActionData = feedbackContext.get(GeneralPKIMessageActionData.class);
//		GeneralPKIMessage generalPKIMessage = feedbackContext.get(GeneralPKIMessage.class);
//		ProtectedPKIMessage protectedPKIMessage = new ProtectedPKIMessage(generalPKIMessage);
//				
//		PKIBody pkiBody = protectedPKIMessage.getBody();
//		CertRepMessage certRepMessage = CertRepMessage.getInstance(pkiBody
//				.getContent());
//		CMPCertificate[] caPubs = certRepMessage.getCaPubs();
//		CMPCertificate requestedCertificate = caPubs[0];
//		
//		new CertificationReplyValidator()
//			.withCertTemplate(certTemplate)
//			.validate(validationResult);
//		KeyStoreWraper keyStoreWraper = feedbackContext.get(KeyStoreWraper.class);
//		for (CMPCertificate cmpCertificate : caPubs) {
//			Certificate x509v3pkCert = cmpCertificate.getX509v3PKCert();
//
//			if (subject != null && !subject.equals(x509v3pkCert.getSubject()))
//				continue;
//
//			if (issuer != null && !issuer.equals(x509v3pkCert.getIssuer()))
//				continue;
//
//			if (publicKey != null && !publicKey
//							.equals(x509v3pkCert.getSubjectPublicKeyInfo()))
//				continue;
//			certificateStore.addCertificate(new X509CertificateHolder(
//					x509v3pkCert));
//		}
	}
}
