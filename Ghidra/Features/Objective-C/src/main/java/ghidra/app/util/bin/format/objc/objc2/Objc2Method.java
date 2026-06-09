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
package ghidra.app.util.bin.format.objc.objc2;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.dyld.LibObjcOptimization;
import ghidra.app.util.bin.format.objc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;

public class Objc2Method extends ObjcMethod {
	private String name;
	private String types;
	private Objc2Implementation imp;

	private LibObjcOptimization libObjcOptimization;
	private boolean isSmall;

	public Objc2Method(Program program, ObjcState state, BinaryReader reader,
			ObjcMethodType methodType, boolean isSmallList) throws IOException {
		super(program, state, reader, methodType);

		libObjcOptimization = state.libObjcOptimization;
		isSmall = isSmallList;

		if (isSmallList) {
			int nameOffset = reader.readNextInt();
			long namePtr;
			if (is32bit) {
				namePtr = reader.readInt(base + nameOffset);
			}
			else {
				if (libObjcOptimization != null) {
					// We are in a DYLD Cache
					if (libObjcOptimization.getRelativeSelectorBaseAddressOffset() > 0) {
						namePtr = libObjcOptimization.getAddr() +
							libObjcOptimization.getRelativeSelectorBaseAddressOffset() + nameOffset;
					}
					else {
						namePtr = base + nameOffset;
					}
				}
				else {
					namePtr = reader.readLong(base + nameOffset);
				}
			}

			name = reader.readAsciiString(namePtr);

			int typesOffset = reader.readNextInt();
			types = reader.readAsciiString(base + 4 + typesOffset);
		}
		else {
			long nameIndex = ObjcUtils.readNextIndex(reader, is32bit);
			name = reader.readAsciiString(nameIndex);

			long typesIndex = ObjcUtils.readNextIndex(reader, is32bit);
			types = reader.readAsciiString(typesIndex);
		}

		imp = new Objc2Implementation(program, state, reader, isSmallList);
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getTypes() {
		return types;
	}

	@Override
	public long getImplementation() {
		return imp.getImplementation();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType("method" + (isSmall ? "_small" : "") + "_t", 0);
		if (isSmall) {
			String comment = "RelativePointer";
			PointerType REL = PointerType.RELATIVE;
			if (libObjcOptimization != null) {
				if (libObjcOptimization.getRelativeSelectorBaseAddressOffset() > 0) {
					struct.add(DWORD, "name",
						comment + " + " + Long.toHexString(libObjcOptimization.getAddr() +
							libObjcOptimization.getRelativeSelectorBaseAddressOffset()));
				}
				else {
					struct.add(new PointerTypedef(null, new PointerDataType(STRING), 4, null,
						PointerType.RELATIVE), "name", comment);
				}
			}
			else {
				struct.add(new PointerTypedef(null, new PointerDataType(STRING), 4, null, REL),
					"name", comment);
			}
			struct.add(new PointerTypedef(null, STRING, 4, null, REL), "types", comment);
			struct.add(new PointerTypedef(null, VOID, 4, null, REL), "imp", comment);
		}
		else {
			struct.add(new PointerDataType(STRING), pointerSize, "name", null);
			struct.add(new PointerDataType(STRING), pointerSize, "types", null);
			struct.add(new PointerDataType(VOID), pointerSize, "imp", null);
		}
		struct.setCategoryPath(Objc2Constants.CATEGORY_PATH);
		return struct;
	}

}
