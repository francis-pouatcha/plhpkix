package org.adorys.plh.pkix.core.cmp.pollrequest;

import java.util.Date;

import org.adorys.plh.pkix.core.cmp.PendingRequestHolder;
import org.adorys.plh.pkix.core.cmp.message.PkiMessageChecker;
import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.stores.PendingPollRequest;
import org.adorys.plh.pkix.core.cmp.utils.ResponseFactory;
import org.apache.commons.lang.time.DateUtils;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;

public class PollReplyProcessor {
	
	private X500Name endEntityName;
	private PendingRequestHolder pendingRequestHolder;
	private CertificateStore certificateStore;
	private PendingPollRequest pendingPollRequest;

	public HttpResponse process0(GeneralPKIMessage generalPKIMessage) {
		try {
		validate();
		
//		CertificateStore certificateStore = CertificateStore.getInstance(endEntityName);
		HttpResponse checkResponse = new PkiMessageChecker().withCertificateStore(certificateStore).check(generalPKIMessage);
		if(checkResponse.getStatusLine().getStatusCode()!=HttpStatus.SC_OK) return checkResponse;
		
		PKIBody pkiBody = generalPKIMessage.getBody();
		PollRepContent pollRepContent = PollRepContent.getInstance(pkiBody.getContent());
		
		pendingRequestHolder.setPollRepMessage(generalPKIMessage.toASN1Structure());

		ASN1Integer checkAfter = pollRepContent.getCheckAfter();
		Date nextPollSeconds = DateUtils.addSeconds(new Date(), checkAfter.getValue().intValue());
		pendingRequestHolder.setNextPoll(nextPollSeconds);
		
		pendingRequestHolder.setPollRepMessage(generalPKIMessage.toASN1Structure());
		
//		PendingPollRequest pendingPollRequest = PendingPollRequest.getInstance(endEntityName);
		pendingPollRequest.storePollRequestHolder(pollRepContent.getCertReqId(), pendingRequestHolder);
		return ResponseFactory.create(HttpStatus.SC_OK, null);
		} finally{
		end();
		}
		
	}
	
	public PollReplyProcessor withEndEntityName(X500Name endEntityName) {
		this.endEntityName = endEntityName;
		return this;
	}
	public PollReplyProcessor withPendingRequestHolder(PendingRequestHolder pendingRequestHolder) {
		this.pendingRequestHolder = pendingRequestHolder;
		return this;
	}

	public PollReplyProcessor withPendingPollRequest(PendingPollRequest pendingPollRequest) {
		this.pendingPollRequest = pendingPollRequest;
		return this;
	}

	public PollReplyProcessor withCertificateStore(CertificateStore certificateStore) {
		this.certificateStore = certificateStore;
		return this;
	}

	private void validate() {
		assert this.endEntityName!=null: "Field endEntityName can not be null";
		assert this.pendingRequestHolder!=null: "Field pendingRequestHolder can not be null";
		assert this.certificateStore!=null: "Field certificateStore can not be null";
		assert this.pendingPollRequest!=null: "Field pendingPollRequest can not be null";
	}

	private void end() {
		this.endEntityName = null;
		this.pendingRequestHolder=null;
		this.certificateStore=null;
		this.pendingPollRequest=null;
	}
}
