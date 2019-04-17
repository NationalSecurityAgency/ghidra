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
//Annotates an HFS+ attributes b-Tree file.
//@category iOS

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.*;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.file.formats.ios.btree.*;
import ghidra.file.formats.ios.decmpfs.DecmpfsHeader;
import ghidra.file.formats.ios.xattr.XattrConstants;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EndianSettingsDefinition;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

public class BTreeAnnotationScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		Address address = currentProgram.getMinAddress();

		ByteProvider provider = new MemoryByteProvider(currentProgram.getMemory(), address);

		BinaryReader reader = new BinaryReader(provider, false);

		BTreeRootNodeDescriptor root = new BTreeRootNodeDescriptor(reader);

		markupRecordOffsets(currentProgram, root, 0, root);

		Data headerNodeData = createBTreeNode(currentProgram, root, 0);

		Data headerRecordData =
			createBTreeHeaderRecord(currentProgram, root.getHeaderRecord(),
				headerNodeData.getLength());

		Data userDataRecordData =
			createUserDataRecord(currentProgram, root.getUserDataRecord(),
				headerNodeData.getLength() + headerRecordData.getLength());

		Data mapRecordData =
			createMapRecord(currentProgram, root.getMapRecord(), headerNodeData.getLength() +
				headerRecordData.getLength() + userDataRecordData.getLength());

		if (mapRecordData == null) {
			printerr("mapRecordData == null ????");
		}

		processNodes(currentProgram, root);
	}

	@Override
	public AnalysisMode getScriptAnalysisMode() {
		return AnalysisMode.DISABLED;
	}

	private int processNodes(Program program, BTreeRootNodeDescriptor root) throws Exception {

		int nodeIndex = 1;
		int min = (int) program.getMinAddress().getOffset();
		int max = (int) program.getMaxAddress().getOffset();
		monitor.setMaximum(max - min);
		monitor.setMessage("Applying node descriptors...");

		int nodeSize = root.getHeaderRecord().getNodeSize() & 0xffff;
		for (int i = nodeSize; i < program.getMemory().getSize(); i += nodeSize) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.setProgress(min + i);

			BTreeNodeDescriptor nodeI = root.getNode(nodeIndex);
			createBTreeNode(program, nodeI, i);

			StringBuffer buffer = new StringBuffer();
			buffer.append("Index:   0x" + Integer.toHexString(nodeIndex) + '\n');
			buffer.append("flink:   0x" + Integer.toHexString(nodeI.getFLink()) + '\n');
			buffer.append("blink:   0x" + Integer.toHexString(nodeI.getBLink()) + '\n');
			buffer.append("kind:      " + nodeI.getKind() + '\n');
			buffer.append("Records: 0x" + Integer.toHexString(nodeI.getNumRecords()) + '\n');

			setPlateComment(toAddr(i), buffer.toString());

			markupBTreeNodeData(program, nodeI);
			markupRecordOffsets(program, root, i, nodeI);

			++nodeIndex;
		}
		return nodeIndex;
	}

	private void markupRecordOffsets(Program program, BTreeRootNodeDescriptor root, int offset,
			BTreeNodeDescriptor nodeI) throws Exception {
		/* TODO
		int pos = 2;
		Address startAddress = toAddr( program, offset + root.getHeaderRecord().getNodeSize() - pos );
		Address currentAddress = startAddress;
		for ( int i = 0 ; i < nodeI.getRecordOffsets().size() ; ++i ) {
			createData( program , currentAddress, new WordDataType() );
			pos += 2;
			currentAddress = currentAddress.subtract( 2 );
		}
		if ( currentAddress.compareTo( startAddress ) < 0 ) {
			createFragment( program , "RecordOffset", currentAddress.add( 2 ), startAddress );
		}
		*/
	}

	private void markupBTreeNodeData(Program program, BTreeNodeDescriptor descriptor)
			throws Exception {

		for (BTreeNodeRecord record : descriptor.getRecords()) {

			Address address = toAddr(record.getRecordOffset());

			DataType recordDataType = record.toDataType();
			Data recordData = createData(address, recordDataType);
			createFragment(record.getType(), recordData.getMinAddress(), recordData.getLength());
			setPlateComment(address,
				record.getType() + " 0x" + Integer.toHexString(record.getFileID()));

			if (descriptor.getKind() == BTreeNodeKinds.kBTLeafNode) {
				if (record.getType().equals(XattrConstants.DECMPFS_XATTR_NAME)) {
					markupDecmpfs(program, descriptor, record, recordData.getMaxAddress().add(1));
				}
				else if (record.getType().equals(XattrConstants.KAUTH_FILESEC_XATTR_NAME)) {
					//TODO
				}
			}
		}
	}

	private void markupDecmpfs(Program program, BTreeNodeDescriptor descriptor,
			BTreeNodeRecord record, Address address) throws Exception {

		DecmpfsHeader header = record.getDecmpfsHeader();
		DataType headerDataType = header.toDataType();
		Data headerData = createData(address, headerDataType);
		changeEndianSettings(headerData);
		createFragment(header.getCompressionMagic(), headerData.getMinAddress(),
			headerData.getLength());
		StringBuffer buffer = new StringBuffer();
		buffer.append(header.getCompressionMagic());
		buffer.append('\n');
		buffer.append("CompressionType: 0x" + Integer.toHexString(header.getCompressionType()));
		buffer.append('\n');
		buffer.append("UncompressedSize: 0x" + Long.toHexString(header.getUncompressedSize()));
		buffer.append('\n');
		setPlateComment(address, buffer.toString());
	}

	private Data createMapRecord(Program program, BTreeMapRecord mapRecord, int offset)
			throws Exception {
		Address address = toAddr(offset);
		DataType dataType = mapRecord.toDataType();
		Data data = createData(address, dataType);
		createFragment(dataType.getName(), data.getMinAddress(), data.getLength());
		return data;
	}

	private Data createUserDataRecord(Program program, BTreeUserDataRecord userDataRecord,
			int offset) throws Exception {
		Address address = toAddr(offset);
		DataType dataType = userDataRecord.toDataType();
		Data data = createData(address, dataType);
		createFragment(dataType.getName(), data.getMinAddress(), data.getLength());
		return data;
	}

	private Data createBTreeHeaderRecord(Program program, BTreeHeaderRecord headerRecord, int offset)
			throws Exception {
		Address address = toAddr(offset);
		DataType dataType = headerRecord.toDataType();
		Data data = createData(address, dataType);
		createFragment(dataType.getName(), data.getMinAddress(), data.getLength());
		return data;
	}

	private Data createBTreeNode(Program program, BTreeNodeDescriptor node, int offset)
			throws Exception {
		Address address = toAddr(offset);
		DataType dataType = node.toDataType();
		Data data = createData(address, dataType);
		createFragment(dataType.getName(), data.getMinAddress(), data.getLength());
		return data;
	}

	private void changeEndianSettings(Data data) throws Exception {
		for (int i = 0; i < data.getNumComponents(); ++i) {
			Data component = data.getComponent(i);
			SettingsDefinition[] settings = component.getDataType().getSettingsDefinitions();
			for (int j = 0; j < settings.length; ++j) {
				if (settings[j] instanceof EndianSettingsDefinition) {
					EndianSettingsDefinition setting = (EndianSettingsDefinition) settings[j];
					setting.setBigEndian(component, false);
				}
			}
		}
	}
}
