package org.adorsys.plh.pkix.workbench.account.register;

/* Imports */
import java.util.List;

import javax.inject.Inject;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import org.adorsys.plh.pkix.client.sedent.identity.DeviceAccount;
import org.adorsys.plh.pkix.client.sedent.identity.DeviceAccountDir;
import org.adorsys.plh.pkix.client.sedent.identity.DeviceAccountRootDir;
import org.adorsys.plh.pkix.client.sedent.identity.LocalAccountExistsException;
import org.adorsys.plh.pkix.workbench.account.utils.AccountMessages;
import org.adorsys.plh.pkix.workbench.account.utils.ValidtionUtils;
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
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.MessageBox;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;

/**
 * The registration View allows the user to enter his email and password to
 * create a new account on this local machine.
 * 
 */
public class RegisterAccountView {

	private static final String SERVICE_NAME = "/messaging";
	private static final String addressPrefix = "http://localhost:8080" + "/plh.pkix.server" + SERVICE_NAME;

	private static final int GRIDDATA_WIDTHHINT = 400;
	private Text userEmail;
	private Button enableProtectionButton;
	private Text protectionQuestion;
	private Label protectionQuestionLabel;
	private Text protectionAnswer;
	private Label protectionAnswerLabel;
	private Text repeatProtectionAnswer;
	private Label repeatProtectionAnswerLabel;
	private Button registerButton;
	
	private Composite parent;

	private MPart registerAccountDialog;

	private EModelService modelService;
	
	private IEclipseContext context;
		
	@Inject
	public RegisterAccountView(Composite p, MPart dialog, EModelService m, IEclipseContext c) {
		this.parent=p;
		this.registerAccountDialog=dialog;
		this.modelService=m;
		this.context = c;
		initDialog();
	}
	
	private void initDialog(){
		IEclipseContext registerAccountDialogContext = registerAccountDialog.getContext();
		final DeviceAccountRootDir deviceDir = registerAccountDialogContext.get(DeviceAccountRootDir.class);

		final Shell shell = parent.getShell();
		ModifyListener enableRegisterModifyListener = new ModifyListener() {
			public void modifyText(ModifyEvent e) {
				enableRegisterButton();
			}
		};
		
		GridLayout layout = new GridLayout();
		layout.numColumns = 2;
		parent.setLayout(layout);
//		Display display = Display.getCurrent();
//		Color blue = display.getSystemColor(SWT.COLOR_BLUE);
//		parent.setBackground(blue);
		parent.getShell().setText(AccountMessages.Register_dialog_title);

		// email label
		Label emailLabel = new Label(parent, SWT.LEFT);
		emailLabel.setText(AccountMessages.Register_dialog_email);
		// The email field
		userEmail = new Text(parent, SWT.BORDER);
		GridData emailGridData = new GridData(GridData.FILL_HORIZONTAL);
		emailGridData.widthHint = GRIDDATA_WIDTHHINT;
		emailGridData.horizontalAlignment = GridData.FILL;
		userEmail.setLayoutData(emailGridData);
		userEmail.addModifyListener(enableRegisterModifyListener);
		
		Label enableProtectionLabel = new Label(parent, SWT.LEFT);
		enableProtectionLabel.setText(AccountMessages.Register_dialog_enableProtection);
		enableProtectionButton=new Button(parent, SWT.CHECK);

		// protection question
		protectionQuestionLabel = new Label(parent, SWT.LEFT);
		protectionQuestionLabel.setText(AccountMessages.Register_dialog_protectionQuestion);
		// The protectionQuestion field
		protectionQuestion= new Text(parent, SWT.BORDER);
		GridData protectionQuestionGridData = new GridData(GridData.FILL_HORIZONTAL);
		protectionQuestionGridData.widthHint = GRIDDATA_WIDTHHINT;
		protectionQuestion.setLayoutData(protectionQuestionGridData);
		protectionQuestion.addModifyListener(enableRegisterModifyListener);
		
		// ProtectionAnswer label
		protectionAnswerLabel = new Label(parent, SWT.LEFT);
		protectionAnswerLabel.setText(AccountMessages.Register_dialog_protectionAnswer);
		// The protectionAnswer field
		protectionAnswer = new Text(parent, SWT.BORDER);
		GridData protectionAnswerGridData = new GridData(GridData.FILL_HORIZONTAL);
		protectionAnswerGridData.widthHint = GRIDDATA_WIDTHHINT;
		protectionAnswer.setLayoutData(protectionAnswerGridData);
		protectionAnswer.addModifyListener(enableRegisterModifyListener);

		// repeatProtectionAnswer label
		repeatProtectionAnswerLabel = new Label(parent, SWT.LEFT);
		repeatProtectionAnswerLabel.setText(AccountMessages.Register_dialog_repeatProtectionAnswer);
		// The repeatProtectionAnswer field
		repeatProtectionAnswer = new Text(parent, SWT.BORDER);
		GridData repeatProtectionAnswerGridData = new GridData(GridData.FILL_HORIZONTAL);
		repeatProtectionAnswerGridData.widthHint = GRIDDATA_WIDTHHINT;
		repeatProtectionAnswer.setLayoutData(repeatProtectionAnswerGridData);
		repeatProtectionAnswer.addModifyListener(enableRegisterModifyListener);
		
		processProtection(false);
		enableProtectionButton.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				processProtection(enableProtectionButton.getSelection());
			}
		});
		
		Composite composite = new Composite(parent, SWT.NONE);
		GridData gridData = new GridData(GridData.HORIZONTAL_ALIGN_FILL);
		gridData.horizontalSpan = 2;
		composite.setLayoutData(gridData);
		layout = new GridLayout();
		layout.numColumns = 2;
		layout.makeColumnsEqualWidth = true;
		composite.setLayout(layout);
		
		Button cancelButton = new Button(composite, SWT.PUSH);
		cancelButton.setText(AccountMessages.Register_dialog_cancel);
		cancelButton.setLayoutData(new GridData(
				GridData.HORIZONTAL_ALIGN_BEGINNING));
		cancelButton.addSelectionListener(new SelectionAdapter() {
			public void widgetSelected(SelectionEvent e) {
				resetFields(parent);
			}
		});
	
		registerButton = new Button(composite, SWT.PUSH);
		registerButton.setText(AccountMessages.Register_dialog_register);
		registerButton.setLayoutData(new GridData(GridData.HORIZONTAL_ALIGN_END));
		registerButton.setEnabled(false);
		registerButton.addSelectionListener(new SelectionAdapter() {
			@SuppressWarnings("restriction")
			public void widgetSelected(SelectionEvent e) {
				String email = userEmail.getText().toLowerCase();
				if (enableProtectionButton.getSelection() && ValidtionUtils.isNotEmptyAndIdentical(protectionAnswer, repeatProtectionAnswer)){
					MessageBox box = new MessageBox(shell, SWT.ICON_INFORMATION
					| SWT.OK | SWT.PRIMARY_MODAL);
					box.setText(AccountMessages.Register_dialog_title);
					box.setMessage(AccountMessages.Register_dialog_both_protectionAnswers_not_identical);
					box.open();
				} else {
					String emailAddress = email;
					boolean emailValid = true;
					try {
						InternetAddress internetAddress = new InternetAddress(email, false);
						emailAddress = internetAddress.getAddress();
					} catch (AddressException e1) {
						emailValid=false;
					}
					if(!emailValid || !ValidtionUtils.validateEmail(emailAddress)){
						MessageBox box = new MessageBox(shell, SWT.ICON_INFORMATION
								| SWT.OK | SWT.PRIMARY_MODAL);
								box.setText(AccountMessages.Register_dialog_title);
								box.setMessage(AccountMessages.Register_dialog_invalide_email);
								box.open();
					} else {
	
						// Register handler here.
						MessageBox box = new MessageBox(shell, SWT.ICON_QUESTION
								| SWT.YES | SWT.PRIMARY_MODAL | SWT.NO);
						box.setText(AccountMessages.Register_dialog_title);
						box.setMessage(AccountMessages.Register_dialog_confirm_address
								+ "\"" + emailAddress + "\"");
						
						int response = box.open();
						if(SWT.YES==response){
							String terminalMessageDescription = null;
							if(enableProtectionButton.getSelection()){
								terminalMessageDescription = protectionQuestion.getText();
							}
							try {
								DeviceAccountDir createdAccount = deviceDir.createAccount(emailAddress, terminalMessageDescription);
								DeviceAccount deviceAccount = null;
								if(StringUtils.isBlank(terminalMessageDescription)){
									deviceAccount = createdAccount.login(null);
								} else {
									deviceAccount = createdAccount.login(protectionAnswer.getText().toCharArray());
								}
								registerAccountDialog.setVisible(false);
								IEventBroker eventBroker = context.get(IEventBroker.class);
								eventBroker.send(DeviceAccount.TOPIC_NAME, deviceAccount);
							} catch (LocalAccountExistsException e1) {
								MessageBox box1 = new MessageBox(shell, SWT.ICON_INFORMATION
										| SWT.OK | SWT.PRIMARY_MODAL);
										box1.setText(AccountMessages.Register_dialog_title);
										box1.setMessage(AccountMessages.Register_dialog_email_exists);
										box1.open();
							}
						} else {
							userEmail.setText(emailAddress);
						}
					}
				}
			}
		});	
		
		// TODO move to a proper method to customize display policy
		List<DeviceAccountDir> loadedAccounts = deviceDir.loadAccounts();
		if(loadedAccounts.isEmpty()){
			registerAccountDialog.setVisible(true);
			modelService.bringToTop(registerAccountDialog);
		}

	}
	
	private void enableRegisterButton(){
		if (registerButton==null) return;
		
		if(!ValidtionUtils.isTextNotEmpty(userEmail)){
			registerButton.setEnabled(false);
			return;
		}
		if(enableProtectionButton==null){
			registerButton.setEnabled(false);
			return;
		}
		
		if(!enableProtectionButton.getSelection()){
			registerButton.setEnabled(true);
			return;			
		}
		
		boolean enabled = ValidtionUtils.isTextNotEmpty(protectionQuestion) &&
				ValidtionUtils.isTextNotEmpty(protectionAnswer) &&
				ValidtionUtils.isTextNotEmpty(repeatProtectionAnswer);
		registerButton.setEnabled(enabled);
	}
	
	private void resetFields(Composite parent){
		if(userEmail!=null)userEmail.setText("");
		if(enableProtectionButton!=null)enableProtectionButton.setSelection(false);
		if(protectionQuestion!=null)protectionQuestion.setText("");
		if(protectionAnswer!=null)protectionAnswer.setText("");
		if(repeatProtectionAnswer!=null)repeatProtectionAnswer.setText("");
		processProtection(false);
		userEmail.setFocus();
	}
	
	private void processProtection(boolean selection) {
		protectionQuestionLabel.setVisible(selection);
		protectionQuestion.setVisible(selection);
		protectionAnswerLabel.setVisible(selection);
		protectionAnswer.setVisible(selection);
		repeatProtectionAnswerLabel.setVisible(selection);
		repeatProtectionAnswer.setVisible(selection);
		enableRegisterButton();
	}

}
