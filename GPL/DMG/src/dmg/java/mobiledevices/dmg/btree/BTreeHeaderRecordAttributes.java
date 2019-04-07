/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.btree;

/**
 * Represents a BTHeaderRec attributes.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-792/bsd/hfs/hfs_format.h.auto.html">hfs/hfs_format.h</a> 
 */
public final class BTreeHeaderRecordAttributes {

	public final static int kBTBadCloseMask = 0x00000001;
	public final static int kBTBigKeysMask = 0x00000002;
	public final static int kBTVariableIndexKeysMask = 0x00000004;

}
