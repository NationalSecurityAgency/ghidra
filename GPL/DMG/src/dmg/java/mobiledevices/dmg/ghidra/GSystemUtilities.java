/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.ghidra;


public class GSystemUtilities {

	public static boolean isEqual(Object o1, Object o2) {
		if (o1 == null) {
			return (o2 == null);
		}
		return o1.equals(o2);
	}

}
