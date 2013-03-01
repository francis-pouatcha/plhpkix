package org.adorsys.plh.pkix.core.smime.utils;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;

public class CloseSubstreamsInputStream extends InputStream {
	private final InputStream delegate;
	private final List<InputStream> substreams = new ArrayList<InputStream>();
	
	public CloseSubstreamsInputStream(InputStream delegate) {
		this.delegate = delegate;
	}


	@Override
	public int read() throws IOException {
		return delegate.read();
	}

	public void addSubstream(InputStream substream){
		substreams.add(substream);
	}


	@Override
	public void close() throws IOException {
		IOUtils.closeQuietly(delegate);
		for (InputStream inputStream : substreams) {
			IOUtils.closeQuietly(inputStream);
		}
	}
	
	
}
