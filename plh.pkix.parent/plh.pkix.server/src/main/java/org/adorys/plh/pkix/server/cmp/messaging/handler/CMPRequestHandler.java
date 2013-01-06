package org.adorys.plh.pkix.server.cmp.messaging.handler;

import javax.ws.rs.core.Response;

import org.bouncycastle.cert.cmp.GeneralPKIMessage;

public abstract class CMPRequestHandler {

	public Response handleRequest(GeneralPKIMessage pkiMessage) {
		return null;
	}

}
