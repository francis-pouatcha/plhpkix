package org.adorys.plh.pkix.core.cmp.pollrequest;

import java.util.Date;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.adorys.plh.pkix.core.cmp.PendingRequestHolder;
import org.adorys.plh.pkix.core.cmp.message.PkiMessageChecker;
import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.stores.PendingPollRequest;
import org.apache.commons.lang.time.DateUtils;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;

public class PollReplyProcessor {
	
	private X500Name endEntityName;
	PendingRequestHolder pendingRequestHolder;
	
	public Response process(GeneralPKIMessage generalPKIMessage) {
		
		validate();
		
		CertificateStore certificateStore = CertificateStore.getInstance(endEntityName);
		Response checkResponse = new PkiMessageChecker().withCertificateStore(certificateStore).check(generalPKIMessage);
		if(checkResponse.getStatus()!=Status.OK.getStatusCode()) return checkResponse;
		
		PKIBody pkiBody = generalPKIMessage.getBody();
		PollRepContent pollRepContent = PollRepContent.getInstance(pkiBody.getContent());
		
		pendingRequestHolder.setPollRepMessage(generalPKIMessage.toASN1Structure());

		ASN1Integer checkAfter = pollRepContent.getCheckAfter();
		Date nextPollSeconds = DateUtils.addSeconds(new Date(), checkAfter.getValue().intValue());
		pendingRequestHolder.setNextPoll(nextPollSeconds);
		
		pendingRequestHolder.setPollRepMessage(generalPKIMessage.toASN1Structure());
		
		PendingPollRequest pendingPollRequest = PendingPollRequest.getInstance(endEntityName);
		pendingPollRequest.storePollRequestHolder(pollRepContent.getCertReqId(), pendingRequestHolder);
		
		end();
		
		return Response.ok().build();
	}
	
	public PollReplyProcessor withEndEntityName(X500Name endEntityName) {
		this.endEntityName = endEntityName;
		return this;
	}

	public PollReplyProcessor withPendingRequestHolder(PendingRequestHolder pendingRequestHolder) {
		this.pendingRequestHolder = pendingRequestHolder;
		return this;
	}

	private void validate() {
		assert this.endEntityName!=null: "Field endEntityName can not be null";
		assert this.pendingRequestHolder!=null: "Field pendingRequestHolder can not be null";
	}

	private void end() {
		this.endEntityName = null;
		this.pendingRequestHolder=null;
	}
}
