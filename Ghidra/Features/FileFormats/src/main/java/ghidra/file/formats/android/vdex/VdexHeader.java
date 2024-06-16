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
package ghidra.file.formats.android.vdex;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.file.formats.android.vdex.sections.DexSectionHeader_002;
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public abstract class VdexHeader implements StructConverter {

	protected String magic_;

	protected VdexStringTable stringTable;
	protected List<Long> dexHeaderStartsList = new ArrayList<>();
	protected List<DexHeader> dexHeaderList = new ArrayList<>();

	protected VdexHeader(BinaryReader reader) throws IOException {
		magic_ = new String(reader.readNextByteArray(VdexConstants.MAGIC.length()));
	}

	public final String getMagic() {
		return magic_;
	}

	public abstract String getVersion();

	public abstract void parse(BinaryReader reader, TaskMonitor monitor)
			throws IOException, CancelledException;

	public final long getDexStartOffset(int index) {
		return dexHeaderStartsList.get(index);
	}

	public abstract int getVerifierDepsSize();

	public abstract int getQuickeningInfoSize();

	public abstract int[] getDexChecksums();

	/**
	 * Returns the list of DEX headers contained in this VDEX.
	 * Could return empty list depending on version of VDEX.
	 */
	public final List<DexHeader> getDexHeaderList() {
		return dexHeaderList;
	}

	/**
	 * Returns the VDEX String Table.
	 * Note: Could be NULL.
	 */
	public final VdexStringTable getStringTable() {
		return stringTable;
	}

	public abstract boolean isDexHeaderEmbeddedInDataType();

	public abstract DexSectionHeader_002 getDexSectionHeader_002();

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(
			magic_ + "_" + getVersion(), 0);
		structure.add(STRING, 4, "magic_", null);
		structure.setCategoryPath(new CategoryPath("/vdex"));
		return structure;
	}
}
