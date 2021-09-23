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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class VdexHeader implements StructConverter {

	protected String magic_;
	protected String verifier_deps_version_;

	protected VdexStringTable stringTable;
	protected List<Long> dexHeaderStartsList = new ArrayList<>();
	protected List<DexHeader> dexHeaderList = new ArrayList<>();

	protected VdexHeader(BinaryReader reader) throws IOException {
		magic_ = new String(reader.readNextByteArray(VdexConstants.MAGIC.length()));
	}

	final public String getMagic() {
		return magic_;
	}

	final public String getVerifierDepsVersion() {
		return verifier_deps_version_;
	}

	abstract public void parse(BinaryReader reader, TaskMonitor monitor)
			throws IOException, CancelledException;

	final public long getDexStartOffset(int index) {
		return dexHeaderStartsList.get(index);
	}

	abstract public int getVerifierDepsSize();

	abstract public int getQuickeningInfoSize();

	abstract public int[] getDexChecksums();

	/**
	 * Returns the list of DEX headers contained in this VDEX.
	 * Could return empty list depending on version of VDEX.
	 */
	final public List<DexHeader> getDexHeaderList() {
		return dexHeaderList;
	}

	/**
	 * Returns the VDEX String Table.
	 * Note: Could be NULL.
	 */
	final public VdexStringTable getStringTable() {
		return stringTable;
	}

	abstract public boolean isDexHeaderEmbeddedInDataType();

	abstract public DexSectionHeader_002 getDexSectionHeader_002();
}
