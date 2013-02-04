package org.adorsys.plh.pkix.client.sedent.identity;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.Properties;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;


/**
 * Holds the client local key pair. Perform signatures and encryptions
 * on behalf of the client.
 * 
 * @author francis
 *
 */
public class AccountDir {
	
	private final DeviceDir deviceDir;
	private final String accountName;
	private final File accountRootDir;
	private final File terminalMessageFile;

	private String terminalSecretImplicite;
	private String terminalMessageDescription;
	
	private static final String TERMINAL_SECRET_IMPLICITE_PROPERTY_NAME="terminal.secret.implicite";
	private static final String TERMINAL_SECRET_DESCRIPTION_PROPERTY_NAME="terminal.secret.description";

	Properties properties =new Properties();
	private AccountDir(DeviceDir deviceDir, String accountName) {
		this.deviceDir = deviceDir;
		this.accountName=accountName;
		this.accountRootDir= new File(deviceDir.getDeviceRootDir(), Md5Utils.toMd5StringHex(accountName));
		
		this.terminalMessageFile = new File(this.accountRootDir,"terminalMessage");
	}
	
	static AccountDir loadAccount(DeviceDir deviceDir, String accountName) throws MissingAccountFilesException{
		AccountDir accountDir = new AccountDir(deviceDir, accountName);
		if(!accountDir.terminalMessageFile.exists())
			throw new MissingAccountFilesException();
		
		accountDir.load();
		return accountDir;
	}
	
	static AccountDir createAccount(DeviceDir deviceDir, String accountName, String terminalMessageDescription) throws LocalAccountExistsException {
		AccountDir accountDir = new AccountDir(deviceDir, accountName);
		
		if(accountDir.terminalMessageFile.exists())
			throw new LocalAccountExistsException();

		if(StringUtils.isNotBlank(terminalMessageDescription)){
			accountDir.terminalMessageDescription = terminalMessageDescription;
		}else {
			accountDir.terminalSecretImplicite=UUID.randomUUID().toString();
		}
		
		accountDir.store();
		
		return accountDir;
	}
//	
//	public void setDescription(String description){
//		this.terminalMessageDescription = description;
//		store();
//	}
	
	/**
	 * The identity of the client.
	 */
	
	public void store(){
		FileOutputStream terminalMessageOutputStream;
		try {
			terminalMessageFile.getParentFile().mkdirs();
			terminalMessageOutputStream = new FileOutputStream(terminalMessageFile);
			if(StringUtils.isNotBlank(terminalMessageDescription))
				properties.put(TERMINAL_SECRET_DESCRIPTION_PROPERTY_NAME, terminalMessageDescription);
			if(StringUtils.isNotBlank(terminalSecretImplicite))
				properties.put(TERMINAL_SECRET_IMPLICITE_PROPERTY_NAME, terminalSecretImplicite);
			properties.store(terminalMessageOutputStream, new Date().toString());
			terminalMessageOutputStream.close();
		} catch (IOException e) {
			throw new IllegalStateException("Error writing terminal Message: " + terminalMessageFile.getPath());
		}
	}
	
	public void load(){
		try {
			FileInputStream terminalMessageInputStream = new FileInputStream(terminalMessageFile);
			properties.load(terminalMessageInputStream);
			terminalSecretImplicite = properties.getProperty(TERMINAL_SECRET_IMPLICITE_PROPERTY_NAME);
			terminalMessageDescription = properties.getProperty(TERMINAL_SECRET_DESCRIPTION_PROPERTY_NAME);
			terminalMessageInputStream.close();
		} catch (IOException e) {
			throw new IllegalStateException("Error reading terminal Message: " + terminalMessageFile.getPath());
		}
	}

	public File getAccountRootDir() {
		return accountRootDir;
	}

	public String getAccountName() {
		return accountName;
	}
	
	public String getDeviceName(){
		return deviceDir.getDeviceIdentity();
	}
	
	public DeviceAccount login(char[] accountPassword){
		return new DeviceAccount(this, accountPassword);
	}

	public String getTerminalSecretImplicite() {
		return terminalSecretImplicite;
	}

	public void setTerminalSecretImplicite(String terminalSecretImplicite) {
		this.terminalSecretImplicite = terminalSecretImplicite;
	}

	public String getTerminalMessageDescription() {
		return terminalMessageDescription;
	}

	public void setTerminalMessageDescription(String terminalMessageDescription) {
		this.terminalMessageDescription = terminalMessageDescription;
	}
	
	
}
