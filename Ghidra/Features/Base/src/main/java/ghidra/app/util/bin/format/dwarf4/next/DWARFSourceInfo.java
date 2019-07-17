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
package ghidra.app.util.bin.format.dwarf4.next;

import ghidra.app.util.bin.format.dwarf4.DIEAggregate;
import ghidra.app.util.bin.format.dwarf4.DebugInfoEntry;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFAttribute;

/**
 * Small class to hold the filename and line number info values from
 * DWARF {@link DebugInfoEntry DIEs}.
 *
 */
public class DWARFSourceInfo {

	/**
	 * Creates a new {@link DWARFSourceInfo} instance from the supplied {@link DIEAggregate}
	 * if the info is present, otherwise returns null;
	 *
	 * @param diea {@link DIEAggregate} to query for source info
	 * @return new {@link DWARFSourceInfo} with filename:linenum info, or null if no info present in DIEA.
	 */
	public static DWARFSourceInfo create(DIEAggregate diea) {
		int fileNum = (int) diea.getUnsignedLong(DWARFAttribute.DW_AT_decl_file, -1);
		int lineNum = (int) diea.getUnsignedLong(DWARFAttribute.DW_AT_decl_line, -1);

		return (fileNum != -1 && lineNum != -1)
				? new DWARFSourceInfo(
					diea.getCompilationUnit().getCompileUnit().getFileByIndex(fileNum), lineNum)
				: null;
	}

	/**
	 * Creates a new {@link DWARFSourceInfo} instance from the supplied {@link DIEAggregate},
	 * falling back to the parent containing DIE record if the first record did not have any
	 * source info.
	 *
	 * @param diea {@link DIEAggregate} to query for source info.
	 * @return new {@link DWARFSourceInfo} with filename:linenum info, or null if no info
	 * present in the specified DIEA and its parent.
	 */
	public static DWARFSourceInfo getSourceInfoWithFallbackToParent(DIEAggregate diea) {
		DWARFSourceInfo dsi = create(diea);
		if (dsi == null) {
			DIEAggregate declParent = diea.getDeclParent();
			if (declParent != null) {
				dsi = create(declParent);
			}
		}
		return dsi;
	}

	/**
	 * Returns the source file and line number info attached to the specified {@link DIEAggregate}
	 * formatted as {@link #getDescriptionStr()}, or null if not present.
	 *
	 * @param diea {@link DIEAggregate} to query
	 * @return string, see {@link #getDescriptionStr()}
	 */
	public static String getDescriptionStr(DIEAggregate diea) {
		DWARFSourceInfo sourceInfo = create(diea);
		return sourceInfo != null ? sourceInfo.getDescriptionStr() : null;
	}

	final private String filename;
	final private int lineNum;

	private DWARFSourceInfo(String filename, int lineNum) {
		this.filename = filename;
		this.lineNum = lineNum;
	}

	/**
	 * Returns the filename
	 *
	 * @return string filename.
	 */
	public String getFilename() {
		return filename;
	}

	/**
	 * Returns the source location info as a string formatted as "filename:linenum"
	 *
	 * @return "filename:linenum"
	 */
	public String getDescriptionStr() {
		return filename + ":" + lineNum;
	}

	/**
	 * Returns the source location info as a string formatted as "File: filename Line: linenum"
	 *
	 * @return "File: filename Line: linenum"
	 */
	public String getDescriptionStr2() {
		return String.format("File: %s Line: %d", filename, lineNum);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((filename == null) ? 0 : filename.hashCode());
		result = prime * result + lineNum;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof DWARFSourceInfo)) {
			return false;
		}
		DWARFSourceInfo other = (DWARFSourceInfo) obj;
		if (filename == null) {
			if (other.filename != null) {
				return false;
			}
		}
		else if (!filename.equals(other.filename)) {
			return false;
		}
		if (lineNum != other.lineNum) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "DWARFSourceInfo [filename=" + filename + ", lineNum=" + lineNum + "]";
	}
}
