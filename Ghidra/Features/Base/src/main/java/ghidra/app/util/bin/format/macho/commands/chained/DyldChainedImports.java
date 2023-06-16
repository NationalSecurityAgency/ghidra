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
package ghidra.app.util.bin.format.macho.commands.chained;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a dyld_chained_import array.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h">mach-o/fixup-chains.h</a> 
 */
public class DyldChainedImports implements StructConverter {

	private int importsCount;
	private int importsFormat;
	private long importsOffset;
	private DyldChainedImport chainedImports[];

	DyldChainedImports(BinaryReader reader, DyldChainedFixupHeader cfh) throws IOException {
		long ptrIndex = reader.getPointerIndex();
		importsOffset = ptrIndex;

		this.importsCount = cfh.getImportsCount();
		this.importsFormat = cfh.getImportsFormat();

		ArrayList<DyldChainedImport> starts = new ArrayList<>();
		for (int i = 0; i < importsCount; i++) {
			starts.add(new DyldChainedImport(reader, cfh, importsFormat));
		}
		chainedImports = starts.toArray(DyldChainedImport[]::new);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType chainedImportDt = chainedImports[0].toDataType();
		DataType dt =
			new ArrayDataType(chainedImportDt, importsCount, chainedImportDt.getLength());

		return dt;
	}

	public int getImportsCount() {
		return importsCount;
	}

	public long getImportsOffset() {
		return importsOffset;
	}

	public DyldChainedImport[] getChainedImports() {
		return chainedImports;
	}

	public DyldChainedImport getChainedImport(int ordinal) {
		if (ordinal < 0 || ordinal >= importsCount) {
			return null;
		}
		return chainedImports[ordinal];
	}

	public void initSymbols(BinaryReader reader, DyldChainedFixupHeader dyldChainedFixupHeader)
			throws IOException {
		long ptrIndex = reader.getPointerIndex();

		for (DyldChainedImport dyldChainedImport : chainedImports) {
			reader.setPointerIndex(ptrIndex + dyldChainedImport.getNameOffset());
			dyldChainedImport.initString(reader);
		}
	}
}
