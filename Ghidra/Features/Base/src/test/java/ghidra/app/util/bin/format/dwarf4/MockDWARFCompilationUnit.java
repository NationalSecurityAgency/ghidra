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
package ghidra.app.util.bin.format.dwarf4;

public class MockDWARFCompilationUnit extends DWARFCompilationUnit {

	private DebugInfoEntry compUnitDIE;
	private MockDWARFProgram dwarfProgram;
	private int dieCount;

	public MockDWARFCompilationUnit(MockDWARFProgram dwarfProgram, long startOffset, long endOffset,
			long length, int format, short version, long abbreviationOffset, byte pointerSize,
			int compUnitNumber, int language) {
		super(dwarfProgram, startOffset, endOffset, length, format, version, abbreviationOffset,
			pointerSize, compUnitNumber, startOffset, null);
		this.dwarfProgram = dwarfProgram;

		this.compUnit = new DWARFCompileUnit("Mock Comp Unit", "Mock Comp Unit Producer",
			"Mock Comp Unit Dir", 0, 0, language, false, null);
	}

	public void setCompUnitDIE(DebugInfoEntry compUnitDIE) {
		this.compUnitDIE = compUnitDIE;
	}

	public DebugInfoEntry getCompileUnitDIE() {
		return compUnitDIE;
	}

	public int incDIECount() {
		return dieCount++;
	}

	@Override
	public MockDWARFProgram getProgram() {
		return dwarfProgram;
	}

	public DWARFAbbreviation createAbbreviation(DWARFAttributeSpecification[] attrSpecs, int tag) {
		DWARFAbbreviation abbr =
			new DWARFAbbreviation(getCodeToAbbreviationMap().size(), tag, true /*??*/, attrSpecs);
		getCodeToAbbreviationMap().put(abbr.getAbbreviationCode(), abbr);

		return abbr;
	}

}
