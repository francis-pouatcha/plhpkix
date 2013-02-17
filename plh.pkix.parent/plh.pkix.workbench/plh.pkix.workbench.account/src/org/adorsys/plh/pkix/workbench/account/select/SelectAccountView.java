package org.adorsys.plh.pkix.workbench.account.select;

/* Imports */
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;

import org.adorsys.plh.pkix.client.sedent.identity.DeviceAccountDir;
import org.adorsys.plh.pkix.client.sedent.identity.DeviceAccount;
import org.adorsys.plh.pkix.client.sedent.identity.DeviceAccountRootDir;
import org.adorsys.plh.pkix.workbench.account.utils.AccountMessages;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.e4.core.contexts.IEclipseContext;
import org.eclipse.e4.core.services.events.IEventBroker;
import org.eclipse.e4.ui.model.application.ui.basic.MPart;
import org.eclipse.e4.ui.workbench.modeling.EModelService;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.ModifyEvent;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;

/**
 * The registration View allows the user to enter his email and password to
 * create a new account on this local machine.
 * 
 */
public class SelectAccountView {

	private static final String SERVICE_NAME = "/messaging";
	private static final String addressPrefix = "http://localhost:8080" + "/plh.pkix.server" + SERVICE_NAME;

	private static final int GRIDDATA_WIDTHHINT = 400;
	private Combo userEmails;
	private Text singleUserEmail;
	private Text protectionQuestion;
	private Text protectionAnswer;
	private Button loginButton;
	
	private EModelService modelService;
	private Composite parent;
	private MPart selectAccountDialog;
	private IEclipseContext context;
	
//	private IEventBroker eventBroker;

	@Inject
	public void initDialog(Composite p, EModelService m, 
			MPart dialog, IEclipseContext c) {
		this.parent = p;
		this.selectAccountDialog = dialog;
		this.modelService=m;
		this.context = c;
		initDialog();
	}
	
	
	private void initDialog(){
		
		IEclipseContext selectAccountDialogContext = selectAccountDialog.getContext();
		final DeviceAccountRootDir deviceDir = selectAccountDialogContext.get(DeviceAccountRootDir.class);
		
		List<DeviceAccountDir> loadedAccounts = deviceDir.loadAccounts();
		if(loadedAccounts.isEmpty()) return;
		
		if(loadedAccounts.size()==1){// handle single account
			initSingleDialog(loadedAccounts.iterator().next());
		} else {// handle multiple accounts
			initMultipleDialog(loadedAccounts);			
		}
	}
	private void initSingleDialog(DeviceAccountDir deviceAccountDir) {
		GridLayout layout = new GridLayout();
		layout.numColumns = 2;
		parent.setLayout(layout);
		parent.getShell().setText(AccountMessages.Select_dialog_title);
		
		// email label
		Label emailLabel = new Label(parent, SWT.LEFT);
		emailLabel.setText(AccountMessages.Select_dialog_email);
		singleUserEmail = new Text(parent, SWT.BORDER| SWT.READ_ONLY);
		singleUserEmail.setText(deviceAccountDir.getDeviceAccountName());
		GridData emailGridData = new GridData(GridData.FILL_HORIZONTAL);
		emailGridData.widthHint = GRIDDATA_WIDTHHINT;
		emailGridData.horizontalAlignment = GridData.FILL;
		singleUserEmail.setLayoutData(emailGridData);
		handleSelection(deviceAccountDir);
	}
	
	private void initMultipleDialog(List<DeviceAccountDir> loadedAccounts){
		
		final Shell shell = parent.getShell();
		GridLayout layout = new GridLayout();
		layout.numColumns = 2;
		parent.setLayout(layout);
		parent.getShell().setText(AccountMessages.Select_dialog_title);
		
		// email label
		Label emailsLabel = new Label(parent, SWT.LEFT);
		emailsLabel.setText(AccountMessages.Select_dialog_email);

		// The email select box
		userEmails = new Combo(parent, SWT.BORDER|SWT.DROP_DOWN|SWT.READ_ONLY);
		userEmails.add(AccountMessages.Select_dialog_email);
		final Map<String, DeviceAccountDir> map = new HashMap<String, DeviceAccountDir>();
		for (DeviceAccountDir accountDir : loadedAccounts) {
			userEmails.add(accountDir.getDeviceAccountName());
			map.put(accountDir.getDeviceAccountName(), accountDir);
		}
		GridData emailGridData = new GridData(GridData.FILL_HORIZONTAL);
//		emailGridData.widthHint = GRIDDATA_WIDTHHINT;
		userEmails.setLayoutData(emailGridData);
		SelectionListener listener = new SelectionListener() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				DeviceAccountDir accountDir = map.get(userEmails.getText());
				if(accountDir!=null)
					handleSelection(accountDir);
			}
			
			@Override
			public void widgetDefaultSelected(SelectionEvent e) {
				DeviceAccountDir accountDir = map.get(userEmails.getText());
				if(accountDir!=null)
					handleSelection(accountDir);
			}
			
		};
		userEmails.addSelectionListener(listener);
	}


	private void handleSelection(final DeviceAccountDir deviceAccountDir) {
//		final String terminalSecretImplicite = deviceAccountDir.getTerminalSecretImplicite();
		if(deviceAccountDir.requiresPassword()){
			String terminalMessageDescription = deviceAccountDir.getDeviceAccountMessageDescription();
			
			// Protection Question label
			Label protectionQuestionLabel = new Label(parent, SWT.LEFT);
			protectionQuestionLabel.setText(AccountMessages.Select_dialog_protectionQuestion);
			// The protectionQuestion field
			protectionQuestion = new Text(parent, SWT.BORDER|SWT.READ_ONLY);
			protectionQuestion.setText(terminalMessageDescription);
			GridData protectionQuestionGridData = new GridData(GridData.FILL_HORIZONTAL);
			protectionQuestionGridData.widthHint = GRIDDATA_WIDTHHINT;
			protectionQuestion.setLayoutData(protectionQuestionGridData);
			
			// Protection Answer label
			Label protectionAnswerLabel = new Label(parent, SWT.LEFT);
			protectionAnswerLabel.setText(AccountMessages.Select_dialog_protectionAnswer);
			// The email field
			protectionAnswer = new Text(parent, SWT.BORDER);
			GridData protectionAnswerGridData = new GridData(GridData.FILL_HORIZONTAL);
			protectionAnswerGridData.widthHint = GRIDDATA_WIDTHHINT;
			protectionAnswer.setLayoutData(protectionAnswerGridData);
			protectionAnswer.setFocus();
		}		
		
		loginButton = new Button(parent, SWT.PUSH);
		loginButton.setText(AccountMessages.Select_dialog_login);
		loginButton.setLayoutData(new GridData(GridData.HORIZONTAL_ALIGN_END));
		enableLoginButton();
	
		if(protectionAnswer!=null){
			protectionAnswer.addModifyListener(new ModifyListener() {
				public void modifyText(ModifyEvent e) {
					enableLoginButton();
				}}
			);
		}
		
		loginButton.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				String terminalSecret = null;
				if(protectionAnswer!=null){
					terminalSecret = protectionAnswer.getText();
					login(deviceAccountDir, terminalSecret.toCharArray());
				} else {
					login(deviceAccountDir, null);// try implicite login
				}
			}
		});

		selectAccountDialog.setVisible(true);
		modelService.bringToTop(selectAccountDialog);
	}
	
	private void enableLoginButton(){
		loginButton.setEnabled(protectionAnswer==null|| StringUtils.isNotBlank(protectionAnswer.getText()));
	}
	
	private void login(DeviceAccountDir accountDir, char[] protectionAnswer){
		DeviceAccount deviceAccount = accountDir.login(protectionAnswer);
		context.set(DeviceAccount.class, deviceAccount);
		// sending this with null data will be equivalent to a logout.
		selectAccountDialog.setVisible(false);
		IEventBroker eventBroker = context.get(IEventBroker.class);
		eventBroker.send(DeviceAccount.TOPIC_NAME, deviceAccount);
	}


}
