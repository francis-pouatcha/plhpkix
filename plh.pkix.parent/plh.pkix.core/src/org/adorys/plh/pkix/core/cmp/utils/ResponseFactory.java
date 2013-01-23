package org.adorys.plh.pkix.core.cmp.utils;

import org.apache.http.HttpResponse;
import org.apache.http.ProtocolVersion;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.message.BasicStatusLine;

public class ResponseFactory {

    public static HttpResponse create(int status, String message){
		return  new BasicHttpResponse(new BasicStatusLine(new ProtocolVersion("http",1,1), status, message));
    }
}
