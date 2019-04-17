/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.ghidra;


/**
 * Class with static methods that deal with string manipulation. 
 */
public class GStringUtilities {

	/**
	 * Converts an integer into a string.
	 * For example, given an integer 0x41424344,
	 * the returned string would be "ABCD".
	 * @param value the integer value
	 * @return the converted string
	 */
	public static String toString(int value) {
		byte[] bytes = new byte[4];
		int byteIndex = bytes.length - 1;
		while (value != 0) {
			bytes[byteIndex] = (byte) value;
			value = value >> 8;
			--byteIndex;
		}
		return new String(bytes);
	}

	public static String convertBytesToString( byte [] bytes, int length ) {
		StringBuffer buf = new StringBuffer( length * 2);
		for ( int i = 0 ; i < length ; ++i ) {
			String bs = Integer.toHexString( bytes[ i ] & 0xff );
			if ( bs.length() == 1 ) {
				buf.append( "0" );
			}
			buf.append( bs );
		}
		return buf.toString();
	}

	public static byte[] convertStringToBytes(String hexstr) {
		try {
			byte[] bytes = new byte[hexstr.length() / 2];
			for (int i = 0; i < hexstr.length(); i += 2) {
				String bs = hexstr.substring(i, i + 2);
				bytes[i / 2] = (byte) Integer.parseInt(bs, 16);
			}
			return bytes;
		}
		catch (Exception e) {
			// tried, but failed
		}
		return null;
	}

}

