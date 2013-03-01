package org.adorsys.plh.pkix.core.cmp.pollrequest;

import java.math.BigInteger;
import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.message.PKIMessageActionData;
import org.adorsys.plh.pkix.core.cmp.stores.PendingRequest;
import org.adorsys.plh.pkix.core.cmp.stores.PendingRequestData;
import org.adorsys.plh.pkix.core.cmp.stores.PendingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PollRepContent;

public class PollReplyStoreActionProcessor implements
		ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(PollReplyStoreActionProcessor.class);
	@Override
	public void process(ActionContext actionContext) {

		PKIMessageActionData actionData = actionContext.get(PKIMessageActionData.class);
		KeyStoreWraper keyStoreWraper = actionContext.get(KeyStoreWraper.class,null);
		PendingRequests pendingRequests = actionContext.get(PendingRequests.class);
		
		checker.checkNull(actionData,keyStoreWraper,pendingRequests);
		
		PKIMessage pkiMessage = actionData.getPkiMessage();
		PKIBody pkiBody = pkiMessage.getBody();
		PollRepContent pollRepContent = PollRepContent.getInstance(pkiBody.getContent());

		ASN1Integer checkAfter = pollRepContent.getCheckAfter();
		Date nextPollSeconds = DateUtils.addSeconds(new Date(), checkAfter.getValue().intValue());
		DERGeneralizedTime nextPoll = new DERGeneralizedTime(nextPollSeconds);
		
		ASN1Integer certReqId = pollRepContent.getCertReqId();
		BigInteger certReqIdBigInteger = pollRepContent.getCertReqId().getPositiveValue();
		PendingRequestData pendingRequestData = pendingRequests.loadPendingRequest(certReqIdBigInteger);
		if(pendingRequestData==null){
			PendingRequest pendingRequest = new PendingRequest(certReqId, pkiMessage, nextPoll);
			pendingRequest.setPollRepMessage(pkiMessage);
			pendingRequestData = new PendingRequestData(pendingRequest);
		} else {
			PendingRequest pendingRequest = pendingRequestData.getPendingRequest();
			pendingRequest.setNextPoll(nextPoll);
			pendingRequest.setPollRepMessage(pkiMessage);
		}
		pendingRequests.storePollRequestHolder(certReqIdBigInteger, pendingRequestData);
	}
}
