package org.adorsys.plh.pkix.client.sedent.identity;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.Properties;
import java.util.UUID;

import org.adorsys.plh.pkix.core.utils.Md5Utils;
import org.adorsys.plh.pkix.core.utils.x500.PlhFileExtensions;
import org.apache.commons.lang3.StringUtils;


/**
 * Holds the client local key pair. Perform signatures and encryptions
 * on behalf of the client.
 * 
 * @author francis
 *
 */
public class DeviceAccountDir {
	
	private static final String TERMINAL_SECRET_IMPLICITE_PROPERTY_NAME="terminal.secret.implicite";
	private static final String TERMINAL_SECRET_DESCRIPTION_PROPERTY_NAME="terminal.secret.description";

	private final DeviceAccountRootDir deviceAccountRootDir;
	private final String deviceAccountName;
	private final File deviceAccountDir;
	private final File deviceAccountMessageFile;

	private String deviceAccountSecretImplicite;
	private String deviceAccountMessageDescription;
	
	Properties properties =new Properties();
	
	private DeviceAccountDir(DeviceAccountRootDir deviceAccountRootDir, String deviceAccountName) {
		this.deviceAccountRootDir = deviceAccountRootDir;
		this.deviceAccountName=deviceAccountName;
		this.deviceAccountDir= new File(this.deviceAccountRootDir.getDeviceRootDir(), 
				Md5Utils.toMd5StringHex(deviceAccountName)+PlhFileExtensions.DEVICE_ACCOUNT_EXT);
		
		this.deviceAccountMessageFile = new File(this.deviceAccountDir,"deviceAccountMessage"+PlhFileExtensions.FILE_PLAIN_EXT);
	}
	
	static DeviceAccountDir loadAccount(DeviceAccountRootDir deviceDir, String accountName) throws MissingAccountFilesException{
		DeviceAccountDir deviceAccountDir = new DeviceAccountDir(deviceDir, accountName);
		if(!deviceAccountDir.deviceAccountMessageFile.exists())
			throw new MissingAccountFilesException();
		
		deviceAccountDir.load();
		return deviceAccountDir;
	}

	static DeviceAccountDir createAccount(DeviceAccountRootDir deviceDir, String accountName, String terminalMessageDescription) throws LocalAccountExistsException {
		DeviceAccountDir accountDir = new DeviceAccountDir(deviceDir, accountName);
		
		if(accountDir.deviceAccountMessageFile.exists())
			throw new LocalAccountExistsException();

		if(StringUtils.isNotBlank(terminalMessageDescription)){
			accountDir.deviceAccountMessageDescription = terminalMessageDescription;
		}else {
			accountDir.deviceAccountSecretImplicite=UUID.randomUUID().toString();
		}
		
		accountDir.store();
		
		return accountDir;
	}
	
	/**
	 * The identity of the client.
	 */
	
	public void store(){
		FileOutputStream terminalMessageOutputStream;
		try {
			deviceAccountMessageFile.getParentFile().mkdirs();
			terminalMessageOutputStream = new FileOutputStream(deviceAccountMessageFile);
			if(StringUtils.isNotBlank(deviceAccountMessageDescription))
				properties.put(TERMINAL_SECRET_DESCRIPTION_PROPERTY_NAME, deviceAccountMessageDescription);
			if(StringUtils.isNotBlank(deviceAccountSecretImplicite))
				properties.put(TERMINAL_SECRET_IMPLICITE_PROPERTY_NAME, deviceAccountSecretImplicite);
			properties.store(terminalMessageOutputStream, new Date().toString());
			terminalMessageOutputStream.close();
		} catch (IOException e) {
			throw new IllegalStateException("Error writing terminal Message: " + deviceAccountMessageFile.getPath());
		}
	}
	
	public void load(){
		try {
			FileInputStream terminalMessageInputStream = new FileInputStream(deviceAccountMessageFile);
			properties.load(terminalMessageInputStream);
			deviceAccountSecretImplicite = properties.getProperty(TERMINAL_SECRET_IMPLICITE_PROPERTY_NAME);
			deviceAccountMessageDescription = properties.getProperty(TERMINAL_SECRET_DESCRIPTION_PROPERTY_NAME);
			terminalMessageInputStream.close();
		} catch (IOException e) {
			throw new IllegalStateException("Error reading terminal Message: " + deviceAccountMessageFile.getPath());
		}
	}

	public DeviceAccount login(char[] accountPassword){
		if(accountPassword!=null){
			return new DeviceAccount(this, accountPassword);
		} else {
			return new DeviceAccount(this, deviceAccountSecretImplicite.toCharArray());
		}
	}
	
	public String getDeviceAccountMessageDescription() {
		return deviceAccountMessageDescription;
	}

	public void setDeviceAccountMessageDescription(
			String deviceAccountMessageDescription) {
		this.deviceAccountMessageDescription = deviceAccountMessageDescription;
	}

	public DeviceAccountRootDir getDeviceAccountRootDir() {
		return deviceAccountRootDir;
	}

	public String getDeviceAccountName() {
		return deviceAccountName;
	}

	public File getDeviceAccountDir() {
		return deviceAccountDir;
	}

	public File getDeviceAccountMessageFile() {
		return deviceAccountMessageFile;
	}

	public boolean requiresPassword(){
		return StringUtils.isBlank(deviceAccountSecretImplicite);
	}
}
