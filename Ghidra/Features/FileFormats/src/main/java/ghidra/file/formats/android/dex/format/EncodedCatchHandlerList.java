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

import java.util.ArrayList;
import java.util.List;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class EncodedCatchHandlerList implements StructConverter {

	private int size;
	private int sizeLength;// in bytes
	private List<EncodedCatchHandler> handlers = new ArrayList<>();

	public EncodedCatchHandlerList(BinaryReader reader) throws IOException {
		LEB128Info leb128 = reader.readNext(LEB128Info::unsigned);
		size = leb128.asUInt32();
		sizeLength = leb128.getLength();

		for (int i = 0; i < size; ++i) {
			handlers.add(new EncodedCatchHandler(reader));
		}
	}

	/**
	 * size of this list, in entries
	 */
	public int getSize() {
		return size;
	}

	public List<EncodedCatchHandler> getHandlers() {
		return handlers;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
//		int unique = 0;
		String name = "encoded_catch_handler_list" + "_" + sizeLength;
		Structure structure = new StructureDataType(name, 0);
		structure.add(ULEB128, sizeLength, "size", null);
//		int index = 0;
//		for ( EncodedCatchHandler handler : handlers ) {
//			DataType dataType = handler.toDataType( );
//			structure.add( dataType, "handler_" + index, null );
//			unique += dataType.getLength( );
//		}
		structure.setCategoryPath(new CategoryPath("/dex/encoded_catch_handler_list"));
//		try {
//			structure.setName( name + "_" + Integer.toHexString( unique ) );
//		}
//		catch ( Exception e ) {
//			// ignore
//		}
		return structure;
	}

}
