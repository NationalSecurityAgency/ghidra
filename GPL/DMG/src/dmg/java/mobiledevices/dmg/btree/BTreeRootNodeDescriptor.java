/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.btree;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import mobiledevices.dmg.ghidra.GBinaryReader;

public class BTreeRootNodeDescriptor extends BTreeNodeDescriptor {

	private BTreeHeaderRecord headerRecord;
	private BTreeUserDataRecord userDataRecord;
	private BTreeMapRecord mapRecord;
	private List<BTreeNodeDescriptor> nodes = new ArrayList<>();

	public BTreeRootNodeDescriptor( GBinaryReader reader ) throws IOException {
		super( reader );

		this.headerRecord   = new BTreeHeaderRecord( reader );
		this.userDataRecord = new BTreeUserDataRecord( reader );
		this.mapRecord      = new BTreeMapRecord( reader, this.headerRecord );

		this.nodes.add( this );

		int nodeSize = this.headerRecord.getNodeSize() & 0xffff;

		for ( int i = nodeSize ; i < reader.length() ; i += nodeSize ) {
			reader.setPointerIndex( i );
			BTreeNodeDescriptor node = new BTreeNodeDescriptor( reader );
			this.nodes.add( node );
			node.readRecordOffsets( reader, i, this.headerRecord );
			node.readRecords( reader, i );
		}

		this.readRecordOffsets( reader, 0, this.headerRecord );
	}

	public BTreeHeaderRecord getHeaderRecord() {
		return this.headerRecord;
	}

	public BTreeUserDataRecord getUserDataRecord() {
		return this.userDataRecord;
	}

	public BTreeMapRecord getMapRecord() {
		return this.mapRecord;
	}

	public BTreeNodeDescriptor getNode( int index ) {
		try {
			return this.nodes.get( index );
		}
		catch (Exception e) {
			return null;
		}
	}

	public List<BTreeNodeDescriptor> getNodes() {
		return this.nodes;
	}

//	@Override
//	public DataType toDataType() throws DuplicateNameException, IOException {
//		//we want to return the super class structure,
//		//this class is synthetic
//		return StructConverterUtil.toDataType( BTreeNodeDescriptor.class );
//	}
}
