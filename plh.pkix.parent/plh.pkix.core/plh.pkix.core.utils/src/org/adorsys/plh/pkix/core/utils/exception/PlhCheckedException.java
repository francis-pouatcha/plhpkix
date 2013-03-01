package org.adorsys.plh.pkix.core.utils.exception;

import java.util.Locale;

import org.bouncycastle.i18n.ErrorBundle;

/**
 * Localized checked exception for plh.
 *  
 * @author francis
 *
 */
public class PlhCheckedException extends Exception {

	private static final long serialVersionUID = 6150716356131309802L;
	protected ErrorBundle message;

    public PlhCheckedException(ErrorBundle message) 
    {
        super(message.getText(Locale.getDefault()));
        this.message = message;
    }

    public PlhCheckedException(ErrorBundle message, Throwable throwable) 
    {
        super(message.getText(Locale.getDefault()), throwable);
        this.message = message;
    }
    
    /**
     * Returns the localized error message of the exception.
     * @return the localized error message as {@link ErrorBundle}
     */
    public ErrorBundle getErrorMessage() 
    {
        return message;
    }
}
