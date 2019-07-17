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
	private List<BTreeNodeDescriptor> nodes = new ArrayList<BTreeNodeDescriptor>();

	public BTreeRootNodeDescriptor( GBinaryReader reader ) throws IOException {
		super( reader );

		headerRecord   = new BTreeHeaderRecord( reader );
		userDataRecord = new BTreeUserDataRecord( reader );
		mapRecord      = new BTreeMapRecord( reader, headerRecord );

		nodes.add( this );

		int nodeSize = headerRecord.getNodeSize() & 0xffff;

		for ( int i = nodeSize ; i < reader.length() ; i += nodeSize ) {
			reader.setPointerIndex( i );
			BTreeNodeDescriptor node = new BTreeNodeDescriptor( reader );
			nodes.add( node );
			node.readRecordOffsets( reader, i, headerRecord );
			node.readRecords( reader, i );
		}

		this.readRecordOffsets( reader, 0, headerRecord );
	}

	public BTreeHeaderRecord getHeaderRecord() {
		return headerRecord;
	}

	public BTreeUserDataRecord getUserDataRecord() {
		return userDataRecord;
	}

	public BTreeMapRecord getMapRecord() {
		return mapRecord;
	}

	public BTreeNodeDescriptor getNode( int index ) {
		try {
			return nodes.get( index );
		}
		catch (Exception e) {
			return null;
		}
	}

	public List<BTreeNodeDescriptor> getNodes() {
		return nodes;
	}

//	@Override
//	public DataType toDataType() throws DuplicateNameException, IOException {
//		//we want to return the super class structure,
//		//this class is synthetic
//		return StructConverterUtil.toDataType( BTreeNodeDescriptor.class );
//	}
}
