/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.util;

/**
 * Helper methods for converting between
 * number data types without negative
 * promotion.
 * <p>
 * Consider using java built-in methods for conversion instead of methods from this
 * class. 
 */ 
public class Conv {
	
	private Conv() {
	}
	
	/**
	 * A byte mask.
	 * 
	 * @deprecated {@link Byte#toUnsignedInt(byte)} will handle most use cases of this constant
	 */
	@Deprecated(forRemoval = true, since = "10.2")
	public static final int BYTE_MASK = 0xff;
    /**
	 * A short mask.
	 * @deprecated {@link Short#toUnsignedInt(short)} will handle most use cases of this constant
	 */
	@Deprecated(forRemoval = true, since = "10.2")
	public static final int SHORT_MASK = 0xffff;
    /**
	 * An integer mask.
	 * @deprecated {@link Integer#toUnsignedLong(int)} will handle most use cases of this constant
	 */
	@Deprecated(forRemoval = true, since = "10.2")
	public static final long INT_MASK = 0x00000000ffffffffL;

    /**
	 * @param b the byte
	 * @return the short equivalent of the byte
	 * @deprecated Use other built-ins like {@link Byte#toUnsignedInt(byte)}
	 */
	@Deprecated(forRemoval = true, since = "10.2")
	public static short byteToShort(byte b) {
        return (short)(b & BYTE_MASK);
    }
    
	/**
	 * Converts a byte to an integer.
	 * 
	 * @param b the byte
	 * @return the integer equivalent of the byte
	 * @deprecated Use {@link Byte#toUnsignedInt(byte)} instead
	 */
	@Deprecated(forRemoval = true, since = "10.2")
	public static int byteToInt(byte b) {
        return (b & BYTE_MASK);
    }
    
	/**
	 * Converts a byte to a long.
	 * @param b the byte
	 * @return the long equivalent of the byte
	 * @deprecated Use {@link Byte#toUnsignedLong(byte)} instead
	 */
	@Deprecated(forRemoval = true, since = "10.2")
	public static long byteToLong(byte b) {
        return intToLong(b & BYTE_MASK);
    }
    
	/**
	 * Converts a short to an integer.
	 * @param s the short
	 * @return the integer equivalent of the short
	 * @deprecated Use {@link Short#toUnsignedInt(short)} instead
	 */
	@Deprecated(forRemoval = true, since = "10.2")
	public static int shortToInt(short s) {
        return (s & SHORT_MASK);
    }
    
	/**
	 * Converts a short to a long.
	 * @param s the short
	 * @return the long eqivalent of the short
	 * @deprecated Use {@link Short#toUnsignedLong(short)} instead
	 */
	@Deprecated(forRemoval = true, since = "10.2")
	public static long shortToLong(short s) {
        return intToLong(s & SHORT_MASK);
    }
    
	/**
	 * Converts an integer to a long.
	 * @param i the integer
	 * @return the long equivalent of the long
	 * @deprecated Use {@link Integer#toUnsignedLong(int)} instead
	 */
	@Deprecated(forRemoval = true, since = "10.2")
	public static long intToLong(int i) {
        return (i & INT_MASK);
    }

	/**
	 * <p>
	 * Old and <b>incorrect</b> way to convert bytes to a String by casting their
	 * values to chars.  Do not use.  Does not seem to be used in current codebase.
	 * <p>
	 * @param array
	 * @return
	 * @deprecated Use {@link String#String(byte[], java.nio.charset.Charset) new String(bytes, StandardCharSets.US_ASCII)}
	 * instead
	 */
	@Deprecated(forRemoval = true, since = "10.2")
	public static String toString(byte [] array) {
		StringBuilder buffer = new StringBuilder();
    	for (byte b : array) {
			buffer.append((char)b);
		}
    	return buffer.toString();
    }

    /**
	 * Consider using {@link String#format(String, Object...) String.format("%02x", b)} instead.
	 * <p>
	 * Converts a byte into a padded hex string.
	 * 
	 * @param b the byte
	 * @return the padded hex string
	 */
	public static String toHexString(byte b) {
        return zeropad(Integer.toHexString(byteToInt(b)), 2);
    }

    /**
	 * Consider using {@link String#format(String, Object...) String.format("%04x", s)} instead.
	 * <p>
	 * Converts a short into a padded hex string.
	 * 
	 * @param s the short
	 * @return the padded hex string
	 */
	public static String toHexString(short s) {
        return zeropad(Integer.toHexString(shortToInt(s)), 4);
    }
    
	/**
	 * Consider using {@link String#format(String, Object...) String.format("%08x", i)} instead.
	 * <p>
	 * Converts an integer into a padded hex string.
	 * 
	 * @param i the integer
	 * @return the padded hex string
	 */
	public static String toHexString(int i) {
        return zeropad(Integer.toHexString(i), 8);
    }

    /**
	 * Consider using {@link String#format(String, Object...) String.format("%016x", l)} instead.
	 * <p>
	 * Converts a long into a padded hex string.
	 * 
	 * @param l the long
	 * @return the padded hex string
	 */
	public static String toHexString(long l) {
        return zeropad(Long.toHexString(l), 16);
    }

    /**
	 * Returns a string that is extended to length len with zeroes.
	 * 
	 * @param s The string to pad
	 * @param len The length of the return string
	 * @return A string that has been left-padded with zeros to be of length len
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
