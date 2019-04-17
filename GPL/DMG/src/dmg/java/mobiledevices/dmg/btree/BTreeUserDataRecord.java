/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.btree;

import java.io.IOException;

import mobiledevices.dmg.ghidra.GBinaryReader;

/**
 * Represents a User Data Record.
 * 
 * @see <a href="https://developer.apple.com/library/archive/technotes/tn/tn1150.html">User Data Record</a> 
 */
public class BTreeUserDataRecord /*implements StructConverter*/ {

	private byte[] unused;

	BTreeUserDataRecord(GBinaryReader reader) throws IOException {
		this.unused = reader.readNextByteArray(128);
	}

	public byte[] getUnused() {
		return unused;
	}

//	@Override
//	public DataType toDataType() throws DuplicateNameException, IOException {
//		return StructConverterUtil.toDataType( this );
//	}
}
