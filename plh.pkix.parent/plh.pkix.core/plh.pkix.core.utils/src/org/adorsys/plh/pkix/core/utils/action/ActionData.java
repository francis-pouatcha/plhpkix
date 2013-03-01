package org.adorsys.plh.pkix.core.utils.action;

import java.io.InputStream;
import java.io.OutputStream;

public interface ActionData {

	public void writeTo(OutputStream outputStream);
	
	public void readFrom(InputStream inputStream);
}
