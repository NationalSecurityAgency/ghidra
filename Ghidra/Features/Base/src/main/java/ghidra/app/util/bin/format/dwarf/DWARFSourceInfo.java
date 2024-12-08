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
package ghidra.app.util.bin.format.dwarf;

import static ghidra.app.util.bin.format.dwarf.DWARFTag.*;
import static ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.*;

import ghidra.app.util.bin.format.dwarf.attribs.DWARFNumericAttribute;

/**
 * Represents the filename and line number info values from DWARF {@link DebugInfoEntry DIEs}.
 * 
 * @param filename String filename 
 * @param lineNum int line number
 */
public record DWARFSourceInfo(String filename, int lineNum) {
	/**
	 * Creates a new {@link DWARFSourceInfo} instance from the supplied {@link DIEAggregate}
	 * if the info is present, otherwise returns null;
	 *
	 * @param diea {@link DIEAggregate} to query for source info
	 * @return new {@link DWARFSourceInfo} with filename:linenum info, or null if no info present in DIEA.
	 */
	public static DWARFSourceInfo create(DIEAggregate diea) {
		DIEAggregate currentDIEA = diea;
		String file = null;
		while (currentDIEA != null && (file = currentDIEA.getSourceFile()) == null) {
			currentDIEA = currentDIEA.getParent();
		}
		if (file == null) {
			return null;
		}
		DWARFNumericAttribute declLineAttr = diea.findAttributeInChildren(DW_AT_decl_line,
			DW_TAG_formal_parameter, DWARFNumericAttribute.class); // TODO: what other children might have a line number attribute?
		if (declLineAttr == null) {
			return null;
		}

		int lineNum = (int) declLineAttr.getUnsignedValue();

		return new DWARFSourceInfo(file, lineNum);
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

	/**
	 * Returns the source location info as a string formatted as "filename:linenum"
	 *
	 * @return "filename:linenum"
	 */
	public String getDescriptionStr() {
		return filename + ":" + lineNum;
	}

	@Override
	public String toString() {
		return "DWARFSourceInfo [filename=" + filename + ", lineNum=" + lineNum + "]";
	}
}
