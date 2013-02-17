package org.adorsys.plh.pkix.server.cmp.utils;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

public class ErrorCommand {

    public static Response error(Status status, String message){
		return Response.status(status).entity(message).build();
    }

    public static Response error(int status, String message){
		return Response.status(status).entity(message).build();
    }
}
