/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.decmpfs;

public final class DecmpfsCompressionTypes {

	/** Uncompressed data in xattr. */
	public final static int CMP_Type1   = 1;

	/** Data stored in-line. */
	public final static int CMP_Type3   = 3;

	/** Resource fork contains compressed data. */
	public final static int CMP_Type4   = 4;

	/** ???? */
	public final static int CMP_Type10  = 10;

	public final static int CMP_MAX     = 255;

}
