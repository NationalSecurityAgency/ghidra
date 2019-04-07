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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class BTreeRootNodeDescriptor extends BTreeNodeDescriptor {

	private BTreeHeaderRecord headerRecord;
	private BTreeUserDataRecord userDataRecord;
	private BTreeMapRecord mapRecord;
	private List<BTreeNodeDescriptor> nodes = new ArrayList<BTreeNodeDescriptor>();

	public BTreeRootNodeDescriptor( BinaryReader reader ) throws IOException {
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

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		//we want to return the super class structure,
		//this class is synthetic
		return StructConverterUtil.toDataType( BTreeNodeDescriptor.class );
	}
}
