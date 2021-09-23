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
package ghidra.file.formats.android.dex.format;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class EncodedCatchHandler implements StructConverter {

	private int size;
	private int sizeLength;// in bytes
	private List<EncodedTypeAddressPair> handlers = new ArrayList<>();
	private int catchAllAddress;
	private int catchAllAddressLength;

	public EncodedCatchHandler(BinaryReader reader) throws IOException {
		LEB128 leb128 = LEB128.readSignedValue(reader);
		size = leb128.asInt32();
		sizeLength = leb128.getLength();

		for (int i = 0; i < Math.abs(size); ++i) {
			handlers.add(new EncodedTypeAddressPair(reader));
		}

		if (size <= 0) {// This element is only present if size is non-positive.
			leb128 = LEB128.readUnsignedValue(reader);
			catchAllAddress = leb128.asUInt32();
			catchAllAddressLength = leb128.getLength();
		}
	}

	/**
	 * <pre>
	 * Number of catch types in this list. If non-positive, then this is the 
	 * negative of the number of catch types, and the catches are followed by a catch-all handler. 
	 * For example: A size of 0 means that there is a catch-all but no explicitly typed catches. 
	 * A size of 2 means that there are two explicitly typed catches and no catch-all. 
	 * And a size of -1 means that there is one typed catch along with a catch-all.
	 * </pre>
	 */
	public int getSize() {
		return size;
	}

	/**
	 * Stream of abs(size) encoded items, one for each caught type, in the order that the types should be tested.
	 */
	public List<EncodedTypeAddressPair> getPairs() {
		return handlers;
	}

	/**
	 * Bytecode address of the catch-all handler. This element is only present if size is non-positive.
	 */
	public int getCatchAllAddress() {
		return catchAllAddress;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StringBuilder builder = new StringBuilder();
		builder.append("encoded_catch_handler_" + sizeLength + "_" + catchAllAddressLength + "_" +
			handlers.size());
		Structure structure = new StructureDataType(builder.toString(), 0);
		structure.add(new ArrayDataType(BYTE, sizeLength, BYTE.getLength()), "size", null);
		int index = 0;
		for (EncodedTypeAddressPair pair : handlers) {
			DataType dataType = pair.toDataType();
			structure.add(dataType, "handler_" + index, null);
			builder.append(pair.getDataTypeIdString());
		}
		if (size <= 0) {// This element is only present if size is non-positive.
			structure.add(new ArrayDataType(BYTE, catchAllAddressLength, BYTE.getLength()),
				"catch_all_addr", null);
		}
		structure.setCategoryPath(new CategoryPath("/dex/encoded_catch_handler"));
		try {
			structure.setName(builder.toString());
		}
		catch (Exception e) {
			// ignore
		}
		return structure;
	}

}
