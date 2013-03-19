package org.adorsys.plh.pkix.core.utils.store;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * @author francis
 *
 */
public class UnprotectedFileWraper implements FileWrapper{

	private String path;
	private File file;
	private File rootFile;
	
	private UnprotectedFileContainer container;
	
	public UnprotectedFileWraper(String path, File rootFile, UnprotectedFileContainer container) {
		super();
		this.path = path;
		this.rootFile = rootFile;
		this.file = new File(rootFile, path);
		this.container = container;
	}

	@Override
	public InputStream newInputStream() {
		if(file.isDirectory()) throw new IllegalArgumentException("FIle is a directory");
		try {
			return new FileInputStream(file);
		} catch (FileNotFoundException e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public OutputStream newOutputStream() {
		if(file.isDirectory()) throw new IllegalArgumentException("FIle is a directory");
		file.getParentFile().mkdirs();
		try {
			return new FileOutputStream(file);
		} catch (FileNotFoundException e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public String getFileRelativePath() {
		return path;
	}

	@Override
	public boolean delete() {
		return file.delete();
	}

	@Override
	public boolean exists() {
		return file.exists();
	}

	@Override
	public String getName() {
		return file.getName();
	}

	@Override
	public String getParent() {
		File parentFile = file.getParentFile();
		if(parentFile.equals(rootFile)) return "/";
		
		return path.substring(0,path.lastIndexOf(file.getName()));
	}

	@Override
	public void integrityCheck() {
		// blank
	}

	@Override
	public String[] list() {
		return file.list();
	}

	@Override
	public FileWrapper newChild(String name) {
		return new UnprotectedFileWraper(name, file, container);
	}

	/**
	 * 
	@Override
	public X509CertificateHolder loadKeyCertificate(String publicKeyIdentifier) {
		return null;
	}
	 */

	@Override
	public KeyStoreWraper getKeyStoreWraper() {
		return null;
	}
}
