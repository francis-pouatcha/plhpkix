package org.adorsys.plh.pkix.core.utils.store;

import java.io.File;

public class UnprotectedFileContainer implements FilesContainer {
	
	private final File rootDir;
	
	public UnprotectedFileContainer(File rootDir) {
		this.rootDir = rootDir;
	}

	@Override
	public FileWrapper newFile(String fileRelativePath) {
		return new UnprotectedFileWraper(fileRelativePath, rootDir, this);
	}

	@Override
	public String getPublicKeyIdentifier() {
		return null;
	}
}
