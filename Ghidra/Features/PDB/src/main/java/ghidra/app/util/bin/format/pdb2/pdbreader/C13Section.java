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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.io.IOException;
import java.io.Writer;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Abstract class for C13 section types.
 */
abstract class C13Section {
	protected static final String dashes =
		"------------------------------------------------------------\n";

	private boolean ignore;

	protected C13Section(boolean ignore) {
		this.ignore = ignore;
	}

	boolean ignore() {
		return ignore;
	}

	void dump(Writer writer) throws IOException {
		String n = getClass().getSimpleName();
		int len = n.length();
		writer.write(n + dashes.substring(len));
		writer.write("End " + n + dashes.substring(len + 4));
	}

	/**
	 * Parse and return a {@link C13Section} of a specific type pointed to by a section record.
	 * @param reader reader to parse from
	 * @param monitor {@link TaskMonitor} used for checking cancellation
	 * @return the parsed data
	 * @throws PdbException Upon not enough data left to parse
	 * @throws CancelledException Upon user cancellation
	 */
	static C13Section parse(PdbByteReader reader, TaskMonitor monitor)
			throws CancelledException, PdbException {
		int typeVal = reader.parseInt();
		boolean ignore = C13Type.ignore(typeVal);
		C13Type type = C13Type.fromValue(typeVal);
		int length = reader.parseInt();
		PdbByteReader recordReader = reader.getSubPdbByteReader(length);

		switch (type) {
			case SYMBOLS:
				return C13Symbols.parse(recordReader, ignore, monitor);
			case LINES:
				return C13Lines.parse(recordReader, ignore, monitor);
			case STRING_TABLE:
				return C13StringTable.parse(recordReader, ignore, monitor);
			case FILE_CHECKSUMS:
				return C13FileChecksums.parse(recordReader, ignore, monitor);
			case FRAMEDATA:
				return C13FrameData.parse(recordReader, ignore, monitor);
			case INLINEE_LINES:
				return C13InlineeLines.parse(recordReader, ignore, monitor);
			case CROSS_SCOPE_IMPORTS:
				return C13CrossScopeImports.parse(recordReader, ignore, monitor);
			case CROSS_SCOPE_EXPORTS:
				return C13CrossScopeExports.parse(recordReader, ignore, monitor);
			case IL_LINES:
				return C13IlLines.parse(recordReader, ignore, monitor);
			case FUNC_MDTOKEN_MAP:
				return C13FuncMdTokenMap.parse(recordReader, ignore, monitor);
			case TYPE_MDTOKEN_MAP:
				return C13TypeMdTokenMap.parse(recordReader, ignore, monitor);
			case MERGED_ASSEMBLY_INPUT:
				return C13MergedAssemblyInput.parse(recordReader, ignore, monitor);
			case COFF_SYMBOL_RVA: // Relative Virtual Address
				return C13CoffSymbolRva.parse(recordReader, ignore, monitor);
			default:
				return UnknownC13Section.parse(recordReader, ignore, monitor);
		}
	}
}
