package org.adorsys.plh.pkix.core.utils.store;

/**
 * Holds files managed by a device or an account.
 * 
 * @author francis
 *
 */
public interface FilesContainer {

	/**
	 * Returns a {@link FileWrapper} that point the relative path.
	 * 
	 * @param fileRelativePath
	 * @return
	 */
	public FileWrapper newFile(String fileRelativePath);

	public FileWrapper newFile(String dirRelativePath, String fileName);
}
