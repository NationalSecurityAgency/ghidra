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
package ghidra.app.util.bin.format.dwarf.macro.entry;

import java.io.IOException;

import ghidra.app.util.bin.format.dwarf.DWARFImporter;
import ghidra.app.util.bin.format.dwarf.attribs.DWARFNumericAttribute;
import ghidra.app.util.bin.format.dwarf.line.DWARFFile;
import ghidra.app.util.bin.format.dwarf.line.DWARFLine;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.database.sourcemap.SourceFileIdType;
import ghidra.util.SourceFileUtils;

/**
 * Represents the start of a source file.
 */
public class DWARFMacroStartFile extends DWARFMacroInfoEntry {

	public DWARFMacroStartFile(DWARFMacroInfoEntry other) {
		super(other);
	}

	public int getLineNumber() throws IOException {
		return getOperand(0, DWARFNumericAttribute.class).getUnsignedIntExact();
	}

	public int getFileNumber() throws IOException {
		return getOperand(1, DWARFNumericAttribute.class).getUnsignedIntExact();
	}

	public SourceFile getSourceFile() throws IOException {
		int fileIndex = getFileNumber();

		DWARFLine dLine = macroHeader.getLine();
		DWARFFile dFile = dLine.getFile(fileIndex);
		String normalizedPath = SourceFileUtils.normalizeDwarfPath(dFile.getPathName(dLine),
			DWARFImporter.DEFAULT_COMPILATION_DIR);
		byte[] md5 = dFile.getMD5();
		SourceFileIdType type = md5 == null ? SourceFileIdType.NONE : SourceFileIdType.MD5;
		return new SourceFile(normalizedPath, type, md5);
	}

	@Override
	public String toString() {
		try {
			return "%s: line: %d, filenum: %d %s".formatted(getName(), getLineNumber(),
				getFileNumber(), getSourceFile());
		}
		catch (IOException e) {
			// ignore
		}
		return super.toString();
	}
}
