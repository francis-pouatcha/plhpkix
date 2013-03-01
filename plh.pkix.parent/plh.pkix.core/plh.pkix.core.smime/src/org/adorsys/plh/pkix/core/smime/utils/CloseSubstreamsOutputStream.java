package org.adorsys.plh.pkix.core.smime.utils;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;

public class CloseSubstreamsOutputStream extends OutputStream {
	private final OutputStream delegate;
	private final List<OutputStream> subStreams = new ArrayList<OutputStream>();
	
	public CloseSubstreamsOutputStream(OutputStream delegate) {
		this.delegate = delegate;
	}
	
	public void addSubStream(OutputStream subStream){
		subStreams.add(subStream);
	}

	@Override
	public void write(int b) throws IOException {
		delegate.write(b);
	}

	@Override
	public void close() throws IOException {
		IOUtils.closeQuietly(delegate);
		for (OutputStream outputStream : subStreams) {
			IOUtils.closeQuietly(outputStream);
		}
	}

}
