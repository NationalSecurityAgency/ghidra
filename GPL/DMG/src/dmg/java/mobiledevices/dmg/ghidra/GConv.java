/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.ghidra;

/**
 * Helper methods for converting between
 * number data types without negative
 * promotion.
 * 
 * 
 */ 
public class GConv {
	
	private GConv() {
	}
	
    /**
     * A byte mask.
     */
    public static final int BYTE_MASK = 0xff;
    /**
     * A short mask.
     */
    public static final int SHORT_MASK = 0xffff;
    /**
     * An integer mask.
     */
    public static final long INT_MASK = 0x00000000ffffffffL;
    /**
     * Converts a byte to a short.
     * @param b the byte
     * @return the short equivalent of the byte
     */
    public static short byteToShort(byte b) {
        return (short)(b & BYTE_MASK);
    }
    /**
     * Converts a byte to an integer.
     * @param b the byte
     * @return the integer equivalent of the byte
     */
    public static int byteToInt(byte b) {
        return (b & BYTE_MASK);
    }
    /**
     * Converts a byte to a long.
     * @param b the byte
     * @return the long equivalent of the byte
     */
    public static long byteToLong(byte b) {
        return intToLong(b & BYTE_MASK);
    }
    /**
     * Converts a short to an integer.
     * @param s the short
     * @return the integer equivalent of the short
     */
    public static int shortToInt(short s) {
        return (s & SHORT_MASK);
    }
    /**
     * Converts a short to a long.
     * @param s the short
     * @return the long eqivalent of the short
     */
    public static long shortToLong(short s) {
        return intToLong(s & SHORT_MASK);
    }
    /**
     * Converts an integer to a long.
     * @param i the integer
     * @return the long equivalent of the long
     */
    public static long intToLong(int i) {
        return (i & INT_MASK);
    }

    public static String toString(byte [] array) {
    	StringBuffer buffer = new StringBuffer();
    	for (byte b : array) {
			buffer.append((char)b);
		}
    	return buffer.toString();
    }
    /**
     * Converts a byte into a padded hex string.
     * @param b the byte
     * @return the padded hex string
     */
    public static String toHexString(byte b) {
        return zeropad(Integer.toHexString(byteToInt(b)), 2);
    }
    /**
     * Converts a short into a padded hex string.
     * @param s the short
     * @return the padded hex string
     */
    public static String toHexString(short s) {
        return zeropad(Integer.toHexString(shortToInt(s)), 4);
    }
    /**
     * Converts an integer into a padded hex string.
     * @param i the integer
     * @return the padded hex string
     */
    public static String toHexString(int i) {
        return zeropad(Integer.toHexString(i), 8);
    }
    /**
     * Converts a long into a padded hex string.
     * @param l the long
     * @return the padded hex string
     */
    public static String toHexString(long l) {
        return zeropad(Long.toHexString(l), 16);
    }

    /**
     * Returns a string that is extended to 
     * length len with zeroes.
     * @param s The string to pad
     * @param len The length of the return string
     * @return A string that has been padded to be of legnth len
     */
    public static String zeropad(String s, int len) {
        if (s == null) s = "";
        StringBuffer buffer = new StringBuffer(s);
        int zerosNeeded = len - s.length();
        for (int i = 0 ; i < zerosNeeded ; ++i) {
            buffer.insert(0, '0');
        }
        return buffer.toString();
    }

}
