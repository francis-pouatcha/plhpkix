package org.adorsys.plh.pkix.client.sedent.storage;

import org.eclipse.osgi.util.NLS;

public class SedentMessages extends NLS {

	private static final String BUNDLE_NAME = "OSGI-INF/l10n/bundle";

	public static final String Sedent_file_files_name="files";
	public static final String Sedent_file_keys_name="keys";

	public static String Sedent_file_files;
	public static String Sedent_file_keys;
	
	static {
		NLS.initializeMessages(BUNDLE_NAME, SedentMessages.class);
	}
}
