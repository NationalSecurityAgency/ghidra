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
import ghidra.app.util.bin.format.objc.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc2ImageInfo extends ObjcTypeMetadataStructure {
	public final static int OBJC_IMAGE_IS_REPLACEMENT = 1 << 0;
	public final static int OBJC_IMAGE_SUPPORTS_GC = 1 << 1;
	public final static int OBJC_IMAGE_REQUIRES_GC = 1 << 2;

	private int version;
	private int flags;

	public Objc2ImageInfo(Program program, ObjcState state, BinaryReader reader)
			throws IOException {
		super(program, state, reader.getPointerIndex());

		version = reader.readNextInt();
		flags = reader.readNextInt();
	}

	public int getVersion() {
		return version;
	}

	public int getFlags() {
		return flags;
	}

	public boolean isReplacement() {
		return (flags & OBJC_IMAGE_IS_REPLACEMENT) != 0;
	}

	public boolean isSupportsGarbageCollection() {
		return (flags & OBJC_IMAGE_SUPPORTS_GC) != 0;
	}

	public boolean isRequiresGarbageCollection() {
		return (flags & OBJC_IMAGE_REQUIRES_GC) != 0;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType("objc_image_info", 0);
		struct.add(DWORD, "version", null);
		struct.add(DWORD, "flags", null);
		struct.setCategoryPath(Objc2Constants.CATEGORY_PATH);
		return struct;
	}

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		Address address = ObjcUtils.toAddress(program, base);
		ObjcUtils.createData(program, toDataType(), address);
	}
}
