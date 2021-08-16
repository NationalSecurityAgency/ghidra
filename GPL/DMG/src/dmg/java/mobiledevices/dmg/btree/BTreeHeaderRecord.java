/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.btree;

import java.io.IOException;

import mobiledevices.dmg.ghidra.GBinaryReader;

/**
 * Represents a BTHeaderRec structure.
 *
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-792/bsd/hfs/hfs_format.h.auto.html">hfs/hfs_format.h</a>
 */
public class BTreeHeaderRecord /*implements StructConverter*/ {

	private short treeDepth;
	private int rootNode;
	private int leafRecords;
	private int firstLeafNode;
	private int lastLeafNode;
	private short nodeSize;
	private short maxKeyLength;
	private int totalNodes;
	private int freeNodes;
	private short reserved1;
	private int clumpSize;
	private byte btreeType;
	private byte keyCompareType;
	private int attributes;
	private int[] reserved;

	BTreeHeaderRecord(GBinaryReader reader) throws IOException {
		this.treeDepth = reader.readNextShort();
		this.rootNode = reader.readNextInt();
		this.leafRecords = reader.readNextInt();
		this.firstLeafNode = reader.readNextInt();
		this.lastLeafNode = reader.readNextInt();
		this.nodeSize = reader.readNextShort();
		this.maxKeyLength = reader.readNextShort();
		this.totalNodes = reader.readNextInt();
		this.freeNodes = reader.readNextInt();
		this.reserved1 = reader.readNextShort();
		this.clumpSize = reader.readNextInt();
		this.btreeType = reader.readNextByte();
		this.keyCompareType = reader.readNextByte();
		this.attributes = reader.readNextInt();
		this.reserved = reader.readNextIntArray(16);
	}

	public short getTreeDepth() {
		return this.treeDepth;
	}

	public int getRootNode() {
		return this.rootNode;
	}

	public int getLeafRecords() {
		return this.leafRecords;
	}

	public int getFirstLeafNode() {
		return this.firstLeafNode;
	}

	public int getLastLeafNode() {
		return this.lastLeafNode;
	}

	public short getNodeSize() {
		return this.nodeSize;
	}

	public short getMaxKeyLength() {
		return this.maxKeyLength;
	}

	public int getTotalNodes() {
		return this.totalNodes;
	}

	public int getFreeNodes() {
		return this.freeNodes;
	}

	public short getReserved1() {
		return this.reserved1;
	}

	public int getClumpSize() {
		return this.clumpSize;
	}

	public byte getBtreeType() {
		return this.btreeType;
	}

	public byte getKeyCompareType() {
		return this.keyCompareType;
	}

	public int getAttributes() {
		return this.attributes;
	}

	public int[] getReserved() {
		return this.reserved;
	}

//	@Override
//	public DataType toDataType() throws DuplicateNameException, IOException {
//		return StructConverterUtil.toDataType( this );
//	}

}
