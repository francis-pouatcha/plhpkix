package org.adorys.plh.pkix.server.cmp.core.utils;

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
//    
//    public static ASN1OctetString newUUIDAsASN1OctetString(){
//		return new DEROctetString(UUIDUtils.uuidToBytes(UUID.randomUUID()));
//    }

    private static byte[] uuidToBytes(UUID uuid)
    {
            long msb = uuid.getMostSignificantBits();
            long lsb = uuid.getLeastSignificantBits();
            
            return uuidToBytes(msb, lsb);
    }
}
