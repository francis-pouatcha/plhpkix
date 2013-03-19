package org.adorsys.plh.pkix.core.smime.contact;

import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;

public class NullSafeFileWrapper implements FileWrapper {

	private FileWrapper delegate;
	
	public NullSafeFileWrapper(FileWrapper delegate) {
		this.delegate = delegate;
	}

	@Override
	public InputStream newInputStream() {
		if(delegate!=null) return delegate.newInputStream();
		throw new IllegalStateException("Delegate is null");
	}

	@Override
	public OutputStream newOutputStream() {
		if(delegate!=null) return delegate.newOutputStream();
		throw new IllegalStateException("Delegate is null");
	}

	@Override
	public String getFileRelativePath() {
		if(delegate!=null) return delegate.getFileRelativePath();
		throw new IllegalStateException("Delegate is null");
	}

	@Override
	public boolean delete() {
		if(delegate!=null) return delegate.delete();
		return true;
	}

	@Override
	public boolean exists() {
		if(delegate!=null) return delegate.exists();
		return false;
	}

	@Override
	public String getName() {
		if(delegate!=null) return delegate.getName();
		throw new IllegalStateException("Delegate is null");

	}

	@Override
	public String getParent() {
		if(delegate!=null) return delegate.getParent();
		throw new IllegalStateException("Delegate is null");
	}

	@Override
	public void integrityCheck() {
		if(delegate!=null) delegate.integrityCheck();
	}

	@Override
	public String[] list() {
		if(delegate!=null) return delegate.list();
		return new String[0];
	}

	@Override
	public FileWrapper newChild(String name) {
		if(delegate!=null) return delegate.newChild(name);
		throw new IllegalStateException("Delegate is null");
	}

	@Override
	public KeyStoreWraper getKeyStoreWraper() {
		if(delegate!=null) return delegate.getKeyStoreWraper();
		return null;
	}

}
