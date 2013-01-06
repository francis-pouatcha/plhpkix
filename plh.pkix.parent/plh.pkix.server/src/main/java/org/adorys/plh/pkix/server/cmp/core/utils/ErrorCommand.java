package org.adorys.plh.pkix.server.cmp.core.utils;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

public class ErrorCommand {

    public static Response error(Status status, String message){
		return Response.status(status).entity(message).build();
    }
}