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
package ghidra.file.formats.dump.userdump;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class Module implements StructConverter {

	public final static String NAME = "MODULE_";

	private long moduleBase;
	private int moduleSize;
	private int moduleNameLength;
	private String moduleName;

	private DumpFileReader reader;
	private long index;

	Module(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setModuleBase(reader.readNextPointer());
		setModuleSize(reader.readNextInt());
		setModuleNameLength(reader.readNextInt());
		setModuleName(reader.readNextAsciiString(getModuleNameLength()));
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME + Long.toHexString(moduleBase), 0);

		struct.add(StructConverter.POINTER, reader.getPointerSize(), "ModuleBase", null);
		struct.add(StructConverter.DWORD, 4, "ModuleSize", null);
		struct.add(StructConverter.DWORD, 4, "ModuleInfoLength", null);
		if (getModuleNameLength() > 0) {
			struct.add(new StringDataType(), getModuleNameLength(), "ModuleInfo", null);
		}

		struct.setCategoryPath(new CategoryPath("/UDMP"));

		return struct;
	}

	/**
	 * @return the moduleBase
	 */
	public long getModuleBase() {
		return moduleBase;
	}

	/**
	 * @param moduleBase the moduleBase to set
	 */
	public void setModuleBase(long moduleBase) {
		this.moduleBase = moduleBase;
	}

	/**
	 * @return the moduleSize
	 */
	public int getModuleSize() {
		return moduleSize;
	}

	/**
	 * @param moduleSize the moduleSize to set
	 */
	public void setModuleSize(int moduleSize) {
		this.moduleSize = moduleSize;
	}

	/**
	 * @return the moduleName
	 */
	public String getModuleName() {
		return moduleName;
	}

	/**
	 * @param moduleName the moduleName to set
	 */
	public void setModuleName(String moduleName) {
		this.moduleName = moduleName;
	}

	/**
	 * @return the moduleNameLength
	 */
	public int getModuleNameLength() {
		return moduleNameLength;
	}

	/**
	 * @param moduleNameLength the moduleNameLength to set
	 */
	public void setModuleNameLength(int moduleNameLength) {
		this.moduleNameLength = moduleNameLength;
	}

}
