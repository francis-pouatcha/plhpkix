package org.adorsys.plh.pkix.workbench.account.register.dialogs;

/* Imports */
import javax.inject.Inject;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

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
public class RegisterView {

	private static final String SERVICE_NAME = "/messaging";
	private static final String addressPrefix = "http://localhost:8080" + "/plh.pkix.server" + SERVICE_NAME;

	private static final int GRIDDATA_WIDTHHINT = 300;
	private Text userEmail;
	private Text userPassword;
	private Text repeatPassword;
	private Button registerButton;

	/**
	 * Class constructor that sets the parent composite and widgets
	 * 
	 * @param parent
	 *            Shell The composite that is the parent of the dialog.
	 */
	@Inject
	public RegisterView(final Composite parent) {
		initDialog(parent);
	}

	
	public void initDialog(Composite parent) {

		final Shell shell = parent.getShell();
		ModifyListener enableRegisterModifyListener = new ModifyListener() {
			public void modifyText(ModifyEvent e) {
				enableRegisterButton();
			}
		};
		
		GridLayout layout = new GridLayout();
		layout.numColumns = 2;
		parent.setLayout(layout);
		parent.getShell().setText(Messages.Register_dialog_title);

		// email label
		Label emailLabel = new Label(parent, SWT.LEFT);
		emailLabel.setText(Messages.Register_dialog_email);
		// The email field
		userEmail = new Text(parent, SWT.BORDER);
		GridData emailGridData = new GridData(GridData.FILL_HORIZONTAL);
		emailGridData.widthHint = GRIDDATA_WIDTHHINT;
		userEmail.setLayoutData(emailGridData);
		userEmail.addModifyListener(enableRegisterModifyListener);

		// password label
		Label passwordLabel = new Label(parent, SWT.LEFT);
		passwordLabel.setText(Messages.Register_dialog_password);
		// The email field
		userPassword = new Text(parent, SWT.BORDER);
		userPassword.setEchoChar('*');
		GridData passwordGridData = new GridData(GridData.FILL_HORIZONTAL);
		passwordGridData.widthHint = GRIDDATA_WIDTHHINT;
		userPassword.setLayoutData(passwordGridData);
		userPassword.addModifyListener(enableRegisterModifyListener);

		// password label
		Label repeatPasswordLabel = new Label(parent, SWT.LEFT);
		repeatPasswordLabel.setText(Messages.Register_dialog_repeat_password);
		// The email field
		repeatPassword = new Text(parent, SWT.BORDER);
		repeatPassword.setEchoChar('*');
		GridData repeatPasswordGridData = new GridData(GridData.FILL_HORIZONTAL);
		repeatPasswordGridData.widthHint = GRIDDATA_WIDTHHINT;
		repeatPassword.setLayoutData(passwordGridData);
		repeatPassword.addModifyListener(enableRegisterModifyListener);
		
		Composite composite = new Composite(parent, SWT.NONE);
		GridData gridData = new GridData(GridData.HORIZONTAL_ALIGN_FILL);
		gridData.horizontalSpan = 2;
		composite.setLayoutData(gridData);
		layout = new GridLayout();
		layout.numColumns = 2;
		layout.makeColumnsEqualWidth = true;
		composite.setLayout(layout);

		Button cancelButton = new Button(composite, SWT.PUSH);
		cancelButton.setText(Messages.Register_dialog_cancel);
		cancelButton.setLayoutData(new GridData(
				GridData.HORIZONTAL_ALIGN_BEGINNING));
		cancelButton.addSelectionListener(new SelectionAdapter() {
			public void widgetSelected(SelectionEvent e) {
				resetFields();
			}
		});
		
		registerButton = new Button(composite, SWT.PUSH);
		registerButton.setText(Messages.Register_dialog_register);
		registerButton.setLayoutData(new GridData(GridData.HORIZONTAL_ALIGN_END));
		registerButton.setEnabled(false);
		registerButton.addSelectionListener(new SelectionAdapter() {
			public void widgetSelected(SelectionEvent e) {
				String email = userEmail.getText().toLowerCase();
//				MasterKeyServiceProxy masterKeyServiceProxy = MasterKeyServiceProxy.findByEmail(email);
//				if(masterKeyServiceProxy!=null){
//					MessageBox box = new MessageBox(parent, SWT.ICON_INFORMATION
//					| SWT.OK | SWT.PRIMARY_MODAL);
//					box.setText(parent.getText());
//					box.setMessage(rm.getResourceString(REGISTER_DIALOG_EMAIL_EXISTS)
//							+ "\"" + userEmail.getText() + "\"");
//					box.open();
//				}
				if (ValidtionUtils.isNotEmptyAndIdentical(userPassword, repeatPassword)){
					MessageBox box = new MessageBox(shell, SWT.ICON_INFORMATION
					| SWT.OK | SWT.PRIMARY_MODAL);
					box.setText(Messages.Register_dialog_title);
					box.setMessage(Messages.Register_dialog_both_passwords_not_identical);
					userPassword.setText("");
					repeatPassword.setText("");
					box.open();
				} else {
					String emailAddress = email;
					try {
						InternetAddress internetAddress = new InternetAddress(email, false);
						emailAddress = internetAddress.getAddress();
					} catch (AddressException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
//					CertificateStore francisCertificateStore = new CertificateStore();
//					PendingCertAnn francisPendingCertAnn = new PendingCertAnn();
//					X500Name francisX500Name = X500NameHelper.makeX500Name("Francis Pouatcha", "fpo@plhpkix.biz");
//					CMPMessagingClient francisClient = new CMPMessagingClient(adminX500Name, addressPrefix, new PrivateKeyHolder(), 
//							francisCertificateStore, new PendingPollRequest(), francisPendingCertAnn, new PendingResponses());

					// Register handler here.
					MessageBox box = new MessageBox(shell, SWT.ICON_INFORMATION
							| SWT.OK | SWT.PRIMARY_MODAL);
					box.setText(Messages.Register_dialog_title);
					box.setMessage(Messages.Register_dialog_done
							+ "\"" + userEmail.getText() + "\"");
					
					box.open();

				}
			}
		});	
	}
	
	private void enableRegisterButton(){
		if(ValidtionUtils.isTextNotEmpty(userEmail) &&
				ValidtionUtils.isTextNotEmpty(userPassword) &&
				ValidtionUtils.isTextNotEmpty(repeatPassword))
		{
			registerButton.setEnabled(true);
		} else {
			registerButton.setEnabled(false);
		}
	}
	
	private void resetFields(){
		if(userEmail!=null)userEmail.setText("");
		if(userPassword!=null)userPassword.setText("");
		if(repeatPassword!=null)repeatPassword.setText("");
	}
}
