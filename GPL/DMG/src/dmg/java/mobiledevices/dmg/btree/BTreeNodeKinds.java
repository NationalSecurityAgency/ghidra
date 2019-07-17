/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.btree;

/**
 * Represents kinds of BTNodeDescriptor.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-792/bsd/hfs/hfs_format.h.auto.html">hfs/hfs_format.h</a>
 * @see <a href="https://developer.apple.com/library/archive/technotes/tn/tn1150.html">B-Trees</a> 
 */
public final class BTreeNodeKinds {

	public final static byte kBTLeafNode = -1;
	public final static byte kBTIndexNode = 0;
	public final static byte kBTHeaderNode = 1;
	public final static byte kBTMapNode = 2;

}
