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
package ghidra.file.formats.iso9660;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

public class ISO9660Header implements StructConverter {

	//Hold all volume descriptors
	private ArrayList<ISO9660BaseVolume> volumeDescriptorSet;
	//HashMaps to hold the LBA index and index size of each path table location
	private HashMap<Integer, Short> typeLIndexSizeTable;
	private HashMap<Integer, Short> typeMIndexSizeTable;
	private HashMap<Integer, Short> supplTypeLIndexSizeTable;
	private HashMap<Integer, Short> supplTypeMIndexSizeTable;

	//Hold the directory from the primary volume descriptor
	//This will be used as a starting point to recurse though the directory tree structure
	//inside of the analyzer
	private ISO9660Directory directory;
	private ISO9660VolumeDescriptor primaryDesc;

	private byte type;

	public ISO9660Header(BinaryReader reader) throws IOException {
		volumeDescriptorSet = new ArrayList<ISO9660BaseVolume>();
		typeLIndexSizeTable = new HashMap<Integer, Short>();
		typeMIndexSizeTable = new HashMap<Integer, Short>();
		supplTypeLIndexSizeTable = new HashMap<Integer, Short>();
		supplTypeMIndexSizeTable = new HashMap<Integer, Short>();

		type = ISO9660Constants.BAD_TYPE; //Bad type to fall into loop

		while (type != ISO9660Constants.VOLUME_DESC_SET_TERMINATOR) {

			// not terminator set
			type = reader.readNextByte();
			reader.setPointerIndex(reader.getPointerIndex() - 1);
			if (type == ISO9660Constants.VOLUME_DESC_BOOT_RECORD) {

				volumeDescriptorSet.add(new ISO9660BootRecordVolumeDescriptor(reader));
			}
			else if (type == ISO9660Constants.VOLUME_DESC_PRIMARY_VOLUME_DESC) {
				primaryDesc = new ISO9660VolumeDescriptor(reader);

				directory = primaryDesc.getDirectoryEntry();

				volumeDescriptorSet.add(primaryDesc);

				typeLIndexSizeTable.put(primaryDesc.getTypeLPathTableLocation(),
					primaryDesc.getLogicalBlockSizeLE());

				typeMIndexSizeTable.put(primaryDesc.getTypeMPathTableLocation(),
					primaryDesc.getLogicalBlockSizeBE());

				if (primaryDesc.getDirectoryEntry().isPaddingFieldPresent()) {
					reader.setPointerIndex(reader.getPointerIndex() - 1);
				}
			}
			else if (type == ISO9660Constants.VOLUME_DESC_SUPPL_VOLUME_DESC) {
				ISO9660VolumeDescriptor supplDesc = new ISO9660VolumeDescriptor(reader);

				volumeDescriptorSet.add(supplDesc);

				supplTypeLIndexSizeTable.put(supplDesc.getTypeLPathTableLocation(),
					supplDesc.getLogicalBlockSizeLE());

				supplTypeMIndexSizeTable.put(supplDesc.getTypeMPathTableLocation(),
					supplDesc.getLogicalBlockSizeBE());

				if (supplDesc.getDirectoryEntry().isPaddingFieldPresent()) {
					reader.setPointerIndex(reader.getPointerIndex() - 1);
				}
			}
		}
		// got terminator set
		volumeDescriptorSet.add(new ISO9660SetTerminator(reader));
	}

	public ISO9660Directory getPrimaryDirectory() {

		return directory;
	}

	public ArrayList<ISO9660BaseVolume> getVolumeDescriptorSet() {
		return volumeDescriptorSet;
	}

	public HashMap<Integer, Short> getTypeLIndexSizeTable() {
		return typeLIndexSizeTable;
	}

	public HashMap<Integer, Short> getTypeMIndexSizeTable() {
		return typeMIndexSizeTable;
	}

	public HashMap<Integer, Short> getSupplTypeLIndexSizeTable() {
		return supplTypeLIndexSizeTable;
	}

	public HashMap<Integer, Short> getSupplTypeMIndexSizeTable() {
		return supplTypeMIndexSizeTable;
	}

	public ISO9660VolumeDescriptor getPrimaryVolumeDescriptor() {
		return primaryDesc;
	}

	/**
	 * Creates a string representation of this class filling in field specifics
	 * when applicable. 
	 * @return the string representation of this class
	 */
	@Override
	public String toString() {
		StringBuffer buff = new StringBuffer();

		for (ISO9660BaseVolume volume : volumeDescriptorSet) {

			buff.append(volume.toString());
		}

		return buff.toString();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struc = new StructureDataType("ISO9660Header", 0);
		DataType data;
		for (ISO9660BaseVolume volume : volumeDescriptorSet) {

			data = volume.toDataType();

			struc.add(data);
		}

		return struc;
	}

}
