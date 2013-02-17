package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;

import org.apache.commons.io.FileUtils;

public class FileCleanup {

	public static final void deleteQuietly(File... files){
		for (File file : files) {
			FileUtils.deleteQuietly(file);
		}
	}
}
