package org.adorsys.plh.pkix.core.utils.asn1;

import org.bouncycastle.asn1.DERBitString;

public class ASN1ProcessingStatus extends DERBitString {
	
    public static final int        ok 				= (1 << 7); 
    public static final int        error   			= (1 << 6);
    public static final int        notification  	= (1 << 5);
    public static final int        request_sent 	= (1 << 4);
    public static final int        response_sent    = (1 << 3);
    public static final int        disposed      	= (1 << 2);
    public static final int        poll_req_sent    = (1 << 1);
    public static final int        poll_rep_sent    = (1 << 0);
    public static final int        unknown     		= (1 << 8);

    public static DERBitString getInstance(Object obj) 
    {
        if (obj instanceof ASN1ProcessingStatus)
        {
            return (ASN1ProcessingStatus)obj;
        }
        return new ASN1ProcessingStatus(DERBitString.getInstance(obj));
    }
    
    /**
     * Basic constructor.
     * 
     * @param status - the bitwise OR of the Status flags giving the listed status above
     */
    public ASN1ProcessingStatus(int status)
    {
        super(getBytes(status), getPadBits(status));
    }

    public ASN1ProcessingStatus(
        DERBitString status)
    {
        super(status.getBytes(), status.getPadBits());
    }

    public String toString()
    {
        if (data.length == 1)
        {
            return "Status: 0x" + Integer.toHexString(data[0] & 0xff);
        }
        return "Status: 0x" + Integer.toHexString((data[1] & 0xff) << 8 | (data[0] & 0xff));
    }
}
