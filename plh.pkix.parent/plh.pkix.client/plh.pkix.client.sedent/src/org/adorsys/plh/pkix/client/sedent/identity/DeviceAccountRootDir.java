package org.adorsys.plh.pkix.client.sedent.identity;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.Md5Utils;
import org.apache.commons.io.FileUtils;


/**
 * Initial access to a device. Holds the list of accounts.
 * 
 * @author francis
 *
 */
public class DeviceAccountRootDir {
	
	private final String deviceIdentity = new HostAndDeviceIdentityProvider().getDeviceIdentity();
	private final File deviceRootDir;
	private final File accountsFile;
	
	private final List<String> accounts;

	public DeviceAccountRootDir(String userDir){
		deviceRootDir = new File(userDir, Md5Utils.toMd5StringHex(deviceIdentity));
		accountsFile = new File(deviceRootDir,"accounts");

		if(accountsFile.exists()){
			List<String> readLines;
			try {
				readLines = FileUtils.readLines(accountsFile);
			} catch (IOException e) {

				throw new IllegalStateException("Can not read account: " + accountsFile.getPath());
			}
			accounts=new ArrayList<String>(readLines);
		} else {
			accounts = new ArrayList<String>();
		}
	}

	public String getDeviceIdentity() {
		return deviceIdentity;
	}

	public File getDeviceRootDir() {
		return deviceRootDir;
	}

	public Collection<String> getAccounts() {
		return Collections.unmodifiableList(accounts);
	}
	
	public DeviceAccountDir loadAccount(String account) throws MissingAccountFilesException, UnknownAccountException{
		if(!accounts.contains(account)) throw new UnknownAccountException();
		return DeviceAccountDir.loadAccount(this, account);
	}

	public DeviceAccountDir createAccount(String account, String terminalMessageDescription) throws LocalAccountExistsException {
		if(accounts.contains(account)) throw new LocalAccountExistsException();
		DeviceAccountDir createdAccount = DeviceAccountDir.createAccount(this, account, terminalMessageDescription);
		accounts.add(account);
		store();
		return createdAccount;
	}
	
	private void store(){
		try {
			FileUtils.writeLines(accountsFile, accounts);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
	
	public List<DeviceAccountDir> loadAccounts() {
		List<DeviceAccountDir> result = new ArrayList<DeviceAccountDir>();
		for (String account : accounts) {
			try {
				result.add(loadAccount(account));
			} catch (MissingAccountFilesException e) {
				throw new IllegalStateException(e);
			} catch (UnknownAccountException e) {
				throw new IllegalStateException(e);
			}
		}
		return result;
	}
}
