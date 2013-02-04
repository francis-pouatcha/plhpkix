package org.adorsys.plh.pkix.client.sedent.identity;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.commons.io.FileUtils;


/**
 * Initial access to a device. Holds the list of accounts.
 * 
 * @author francis
 *
 */
public class DeviceDir {
	
	private final String deviceIdentity = new HostAndDeviceIdentityProvider().getDeviceIdentity();
	private final File deviceRootDir;
	private final File accountsFile;
	
	private final List<String> accounts;

	public DeviceDir(String userDir){
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
	
	public AccountDir loadAccount(String account) throws MissingAccountFilesException, UnknownAccountException{
		if(!accounts.contains(account)) throw new UnknownAccountException();
		return AccountDir.loadAccount(this, account);
	}

	public AccountDir createAccount(String account, String terminalMessageDescription) throws LocalAccountExistsException {
		if(accounts.contains(account)) throw new LocalAccountExistsException();
		AccountDir createdAccount = AccountDir.createAccount(this, account, terminalMessageDescription);
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
	
	public List<AccountDir> loadAccounts() {
		List<AccountDir> result = new ArrayList<AccountDir>();
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
