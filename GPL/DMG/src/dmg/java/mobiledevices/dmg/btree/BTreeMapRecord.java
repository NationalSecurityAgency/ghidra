/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.btree;

import java.io.IOException;

import mobiledevices.dmg.ghidra.GBinaryReader;

/**
 * Represents a Map Record.
 * 
 * @see <a href="https://developer.apple.com/library/archive/technotes/tn/tn1150.html">Map Record</a> 
 */
public class BTreeMapRecord /*implements StructConverter*/ {

	private byte[] bitmap;

	protected BTreeMapRecord(GBinaryReader reader, BTreeHeaderRecord headerRecord)
			throws IOException {
		this.bitmap = reader.readNextByteArray(headerRecord.getNodeSize() - 256);
	}

	/**
	 * Returns the map record node allocation bitmap.
	 * @return the map record node allocation bitmap
	 */
	public byte[] getBitmap() {
		return bitmap;
	}

	/**
	 * Returns  true if the specified node index is used.
	 * Returns false if the specified node index is free.
	 * @param nodeIndex the node index
	 * @return true if the specified node index is used, false if free
	 */
	public boolean isNodeUsed(int nodeIndex) {
		int block = bitmap[nodeIndex / 8] & 0xff;
		return (block & (1 << 7 - (nodeIndex % 8))) != 0;
	}

//	@Override
//	public DataType toDataType() throws DuplicateNameException, IOException {
//		return StructConverterUtil.toDataType( this );
//	}
}
