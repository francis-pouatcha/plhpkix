package org.adorsys.plh.pkix.core.utils.jca;

import java.io.IOException;
import java.util.Arrays;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * callback handler for passing password to Provider.login method
 */
public class PasswordCallbackHandler implements CallbackHandler {

	private char[] password;

	public PasswordCallbackHandler(char[] password) {
		if (password != null) {
			this.password = (char[]) password.clone();
		}
	}

	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		if (!(callbacks[0] instanceof PasswordCallback)) {
			throw new UnsupportedCallbackException(callbacks[0]);
		}
		PasswordCallback pc = (PasswordCallback) callbacks[0];
		pc.setPassword(password); // this clones the password if not null
	}

	protected void finalize() throws Throwable {
		if (password != null) {
			Arrays.fill(password, ' ');
		}
		super.finalize();
	}
}