package org.adorsys.plh.pkix.core.cmp;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivators;
import org.adorsys.plh.pkix.core.cmp.initrequest.sender.InitializationRequestFieldHolder;
import org.adorsys.plh.pkix.core.cmp.initrequest.sender.OutgoingInitializationRequestInitActionProcessor;
import org.adorsys.plh.pkix.core.cmp.message.ExecutorConstants;
import org.adorsys.plh.pkix.core.cmp.registration.RegsitrationRequestInitActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;

public class CMPAccount {

	private ActionContext accountContext;

	public CMPAccount(FileWrapper accountDir, ActionContext accountContext) {
		this.accountContext = accountContext;

		ModuleActivators moduleActivators = new ModuleActivators(accountContext, accountDir);
		
		ExecutorService executors_out = Executors.newFixedThreadPool(5);
		accountContext.put(Executor.class, ExecutorConstants.OUTGOING_REQUEST_EXECUTOR_NAME, executors_out);
		ExecutorService executors_in = Executors.newFixedThreadPool(5);
		accountContext.put(Executor.class, ExecutorConstants.INCOMMING_REQUEST_EXECUTOR_NAME, executors_in);		

		CMPMessageEndpoint cmpMessageEndpoint = new AsynchCMPMessageEndpoint(executors_in, new DispatchingCMPMessageEndpoint(moduleActivators, accountContext));
		accountContext.put(CMPMessageEndpoint.class, cmpMessageEndpoint);
		
	}
	
	/**
	 * Register's this account with the messaging server.
	 */
	public void registerAccount(){
		KeyStoreWraper keyStoreWraper = accountContext.get(KeyStoreWraper.class);
		PrivateKeyEntry caPrivateKeyEntry = keyStoreWraper.findAnyCaPrivateKeyEntry();
		PrivateKeyEntry messagePrivateKeyEntry = keyStoreWraper.findAnyMessagePrivateKeyEntry();
		registerAccount(caPrivateKeyEntry);
		registerAccount(messagePrivateKeyEntry);
	}
	
	private void registerAccount(PrivateKeyEntry privateKeyEntry){
		ActionContext actionContext = new ActionContext(accountContext);
		accountContext.put(PrivateKeyEntry.class, privateKeyEntry);
		RegsitrationRequestInitActionProcessor processor = actionContext.get(RegsitrationRequestInitActionProcessor.class);	
		processor.process(actionContext);
	}

	/**
	 * Sends an initialization request to another user, using the user's email.
	 * 
	 * @param email
	 */
	public void sendInitializationRequest(InitializationRequestFieldHolder f) {
		ActionContext actionContext = new ActionContext(accountContext);
		accountContext.put(InitializationRequestFieldHolder.class, f);
		OutgoingInitializationRequestInitActionProcessor actionProcessor = accountContext.get(OutgoingInitializationRequestInitActionProcessor.class);
		actionProcessor.process(actionContext);
	}
}
