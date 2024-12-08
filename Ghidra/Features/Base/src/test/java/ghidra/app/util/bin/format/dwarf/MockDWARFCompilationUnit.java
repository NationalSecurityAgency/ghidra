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

import java.util.Map;

import ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.AttrDef;

public class MockDWARFCompilationUnit extends DWARFCompilationUnit {

	private int dieCount;

	public MockDWARFCompilationUnit(MockDWARFProgram dwarfProgram, long startOffset, long endOffset,
			int intSize, short version, byte pointerSize, int compUnitNumber) {
		super(dwarfProgram, startOffset, endOffset, intSize, version, pointerSize,
			compUnitNumber, startOffset, null);
	}

	public DebugInfoEntry getCompileUnitDIE() {
		return diea.getHeadFragment();
	}

	public int incDIECount() {
		return dieCount++;
	}

	@Override
	public MockDWARFProgram getProgram() {
		return (MockDWARFProgram) dprog;
	}

	public DWARFAbbreviation createAbbreviation(AttrDef[] attrSpecs, DWARFTag tag) {
		Map<Integer, DWARFAbbreviation> map = getCodeToAbbreviationMap();
		DWARFAbbreviation abbr =
			new DWARFAbbreviation(map.size(), tag.getId(), true /*??*/, attrSpecs);
		map.put(abbr.getAbbreviationCode(), abbr);

		return abbr;
	}

}
