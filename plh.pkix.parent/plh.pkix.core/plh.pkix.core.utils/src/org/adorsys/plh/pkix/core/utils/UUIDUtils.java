package org.adorsys.plh.pkix.core.utils;

import java.math.BigInteger;
import java.util.UUID;

public class UUIDUtils {

    public static byte[] newUUIDAsBytes()
    {
    	return uuidToBytes(UUID.randomUUID());
    }
    
    public static byte[] uuidToBytes(long msb, long lsb) {
                            
            byte[] buffer = new byte[16];

            for (int i = 0; i < 8; i++) {
                    buffer[i] = (byte) (msb >>> 8 * (7 - i));
            }
            for (int i = 8; i < 16; i++) {
                    buffer[i] = (byte) (lsb >>> 8 * (7 - i));
            }

            return buffer;
    }

    private static byte[] uuidToBytes(UUID uuid)
    {
            long msb = uuid.getMostSignificantBits();
            long lsb = uuid.getLeastSignificantBits();
            
            return uuidToBytes(msb, lsb);
    }

    public static BigInteger toBigInteger(UUID uuid)
    {
        return new BigInteger(1, uuidToBytes(uuid));
    }
}
