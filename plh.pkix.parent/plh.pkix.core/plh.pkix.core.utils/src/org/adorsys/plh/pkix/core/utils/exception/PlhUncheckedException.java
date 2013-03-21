package org.adorsys.plh.pkix.core.utils.exception;

import java.util.Locale;

import org.adorsys.plh.pkix.core.utils.store.PlhPkixCoreMessages;
import org.bouncycastle.i18n.ErrorBundle;

/**
 * Localized checked exception for plh.
 *  
 * @author francis
 *
 */
public class PlhUncheckedException extends RuntimeException {

	private static final long serialVersionUID = 6150716356131309802L;
	protected ErrorBundle message;

    public PlhUncheckedException(ErrorBundle message) 
    {
        super(message.getText(Locale.getDefault()));
        this.message = message;
    }

    public PlhUncheckedException(ErrorBundle message, Throwable throwable) 
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
    
	private static final String RESOURCE_NAME = PlhPkixCoreMessages.class.getName();    
    public static ErrorBundle toErrorMessage(Exception e, String location){
		return new ErrorBundle(RESOURCE_NAME,
				PlhPkixCoreMessages.PlhUncheckedException_uncaught_exception,
				new Object[] { location, e.getMessage(),e.getClass().getName()});
    }

    public static ErrorBundle toErrorMessage(Exception e, Class<?> location){
		return new ErrorBundle(RESOURCE_NAME,
				PlhPkixCoreMessages.PlhUncheckedException_uncaught_exception,
				new Object[] { location.getName(), e.getMessage(),e.getClass().getName()});
    }
    
    public static PlhUncheckedException toException(String resName, String messageKey){
		ErrorBundle msg = new ErrorBundle(resName,messageKey);
		return new PlhUncheckedException(msg);
    }
    
    public static PlhUncheckedException toException(String resName, String messageKey, Object[] values){
		ErrorBundle msg = new ErrorBundle(resName,messageKey,values);
		return new PlhUncheckedException(msg);
    }

    public static PlhUncheckedException toException(String resName, String messageKey, Exception e, Class<?> location){
		ErrorBundle msg = new ErrorBundle(resName,messageKey, 
				new Object[] { location, e.getMessage(),e.getClass().getName()});
		return new PlhUncheckedException(msg);
    }

    public static PlhUncheckedException toException(Exception e, Class<?> location){
		ErrorBundle msg = toErrorMessage(e, location);
		return new PlhUncheckedException(msg);
    }
}
