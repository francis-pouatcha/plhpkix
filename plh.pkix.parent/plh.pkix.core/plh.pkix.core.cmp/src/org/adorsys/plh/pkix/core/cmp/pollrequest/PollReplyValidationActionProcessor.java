package org.adorsys.plh.pkix.core.cmp.pollrequest;

import java.util.ArrayList;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.certrequest.CertRequestMessages;
import org.adorsys.plh.pkix.core.cmp.message.CertificateValidatingProcessingResult;
import org.adorsys.plh.pkix.core.cmp.message.PKIMessageActionData;
import org.adorsys.plh.pkix.core.cmp.message.PkiMessageChecker;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.i18n.ErrorBundle;

public class PollReplyValidationActionProcessor implements ActionProcessor{

	private static final String RESOURCE_NAME = CertRequestMessages.class
			.getName();

	BuilderChecker checker = new BuilderChecker(PollReplyValidationActionProcessor.class);
	@Override
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
		
		PKIMessage pkiMessage = messageActionData.getPkiMessage();
		PKIBody pkiBody = pkiMessage.getBody();
		PollRepContent pollRepContent = PollRepContent.getInstance(pkiBody.getContent());
		
		ASN1Integer certReqId = pollRepContent.getCertReqId();
		if(certReqId==null){
			// add error
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CertRequestMessages.response.missingCertRequestId");
			processingResults.addError(msg);
		}

		// Validate Results and route processing
		PollReplyValidationPostAction postAction = new PollReplyValidationPostAction(actionContext, processingResults);
		List<Action> actions = new ArrayList<Action>();
		actions.add(postAction);
		actionHandler.handle(actions);		
	}
}
