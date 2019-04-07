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
package ghidra.file.formats.ios.btree;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a BTHeaderRec structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-792/bsd/hfs/hfs_format.h.auto.html">hfs/hfs_format.h</a> 
 */
public class BTreeHeaderRecord implements StructConverter {

	private short    treeDepth;
	private int      rootNode;
	private int      leafRecords;
	private int      firstLeafNode;
	private int      lastLeafNode;
	private short    nodeSize;
	private short    maxKeyLength;
	private int      totalNodes;
	private int      freeNodes;
	private short    reserved1;
	private int      clumpSize;
	private byte     btreeType;
	private byte     keyCompareType;
	private int      attributes;
	private int []   reserved;

	BTreeHeaderRecord( BinaryReader reader ) throws IOException {
		this.treeDepth       =  reader.readNextShort();
		this.rootNode        =  reader.readNextInt();
		this.leafRecords     =  reader.readNextInt();
		this.firstLeafNode   =  reader.readNextInt();
		this.lastLeafNode    =  reader.readNextInt();
		this.nodeSize        =  reader.readNextShort();
		this.maxKeyLength    =  reader.readNextShort();
		this.totalNodes      =  reader.readNextInt();
		this.freeNodes       =  reader.readNextInt();
		this.reserved1       =  reader.readNextShort();
		this.clumpSize       =  reader.readNextInt();
		this.btreeType       =  reader.readNextByte();
		this.keyCompareType  =  reader.readNextByte();
		this.attributes      =  reader.readNextInt();
		this.reserved        =  reader.readNextIntArray( 16 );
	}

	public short getTreeDepth() {
		return treeDepth;
	}

	public int getRootNode() {
		return rootNode;
	}

	public int getLeafRecords() {
		return leafRecords;
	}

	public int getFirstLeafNode() {
		return firstLeafNode;
	}

	public int getLastLeafNode() {
		return lastLeafNode;
	}

	public short getNodeSize() {
		return nodeSize;
	}

	public short getMaxKeyLength() {
		return maxKeyLength;
	}

	public int getTotalNodes() {
		return totalNodes;
	}

	public int getFreeNodes() {
		return freeNodes;
	}

	public short getReserved1() {
		return reserved1;
	}

	public int getClumpSize() {
		return clumpSize;
	}

	public byte getBtreeType() {
		return btreeType;
	}

	public byte getKeyCompareType() {
		return keyCompareType;
	}

	public int getAttributes() {
		return attributes;
	}

	public int [] getReserved() {
		return reserved;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType( this );
	}
	
}
