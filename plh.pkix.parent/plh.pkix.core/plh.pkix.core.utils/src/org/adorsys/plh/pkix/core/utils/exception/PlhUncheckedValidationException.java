package org.adorsys.plh.pkix.core.utils.exception;

import java.util.List;
import java.util.Locale;

import org.bouncycastle.i18n.ErrorBundle;

/**
 * Localized checked exception for plh.
 *  
 * @author francis
 *
 */
public class PlhUncheckedValidationException extends RuntimeException {

	private static final long serialVersionUID = 6150716356131309802L;
	protected List<ErrorBundle> messages;

    public PlhUncheckedValidationException(List<ErrorBundle> messages) 
    {
        super(messages.get(0).getText(Locale.getDefault()));
        this.messages = messages;
    }
    
    /**
     * Returns the localized error message of the exception.
     * @return the localized error message as {@link ErrorBundle}
     */
    public List<ErrorBundle> getErrorMessages() 
    {
        return messages;
    }
}
