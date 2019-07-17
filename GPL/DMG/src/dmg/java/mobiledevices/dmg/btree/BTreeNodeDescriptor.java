/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.btree;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import mobiledevices.dmg.ghidra.GBinaryReader;

/**
 * Represents a BTNodeDescriptor structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-792/bsd/hfs/hfs_format.h.auto.html">hfs/hfs_format.h</a> 
 */
public class BTreeNodeDescriptor /*implements StructConverter*/ {

	private int fLink;
	private int bLink;
	private byte kind;
	private byte height;
	private short numRecords;
	private short reserved;

	private List<Short> _recordOffsets = new ArrayList<Short>();
	private List<BTreeNodeRecord> _records = new ArrayList<BTreeNodeRecord>();

	BTreeNodeDescriptor(GBinaryReader reader) throws IOException {
		this.fLink = reader.readNextInt();
		this.bLink = reader.readNextInt();
		this.kind = reader.readNextByte();
		this.height = reader.readNextByte();
		this.numRecords = reader.readNextShort();
		this.reserved = reader.readNextShort();
	}

	protected void readRecordOffsets(GBinaryReader reader, long nodeStartIndex,
			BTreeHeaderRecord header) throws IOException {
		long position = nodeStartIndex + header.getNodeSize() - 2;
		while (true) {
			short recordOffset = reader.readShort(position);
			if (recordOffset == 0) {
				break;
			}
			_recordOffsets.add(recordOffset);
			position = position - 2;
		}
	}

	protected void readRecords(GBinaryReader reader, long nodeStartIndex) throws IOException {
		for (int i = 0; i < getNumRecords(); ++i) {

			short offset = getRecordOffsets().get(i);

			long recordIndex = (offset & 0xffff) + nodeStartIndex;
			reader.setPointerIndex(recordIndex);

			BTreeNodeRecord record = new BTreeNodeRecord(reader, this);
			_records.add(record);
		}
	}

	public List<Short> getRecordOffsets() {
		return _recordOffsets;
	}

	public List<BTreeNodeRecord> getRecords() {
		return _records;
	}

	/**
	 * The node number of the next node of this type.
	 * Or, zero ( 0 ) if this is the last node.
	 * @return node number of the next node of this type
	 */
	public int getFLink() {
		return fLink;
	}

	/**
	 * The node number of the previous node of this type.
	 * Or, zero ( 0 ) if this is the first node.
	 * @return node number of the previous node of this type
	 */
	public int getBLink() {
		return bLink;
	}

	/**
	 * Returns the key of this node.
	 * @return the key of this node
	 * @see BTreeNodeKinds
	 */
	public byte getKind() {
		return kind;
	}

	/**
	 * Returns the level, or depth, of this node in the B-tree hierarchy.
	 * @return the level, or depth, of this node in the B-tree hierarchy
	 */
	public byte getHeight() {
		return height;
	}

	/**
	 * Returns the number of records in this node.
	 * @return the number of records in this node
	 */
	public short getNumRecords() {
		return numRecords;
	}

	/**
	 * This field is reserved.
	 * @return this field is reserved
	 */
	public short getReserved() {
		return reserved;
	}

//	@Override
//	public DataType toDataType() throws DuplicateNameException, IOException {
//		return StructConverterUtil.toDataType( this );
//	}

}
