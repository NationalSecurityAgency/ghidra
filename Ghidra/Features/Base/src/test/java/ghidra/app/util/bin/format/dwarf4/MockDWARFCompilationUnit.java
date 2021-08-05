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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.dwarf4.encoding.*;
import ghidra.app.util.bin.format.dwarf4.next.DWARFProgram;
import ghidra.util.task.TaskMonitor;

public class MockDWARFCompilationUnit extends DWARFCompilationUnit {

	private List<DebugInfoEntry> mockEntries = new ArrayList<>();
	private DebugInfoEntry compUnitDIE;

	public MockDWARFCompilationUnit(DWARFProgram dwarfProgram, long startOffset, long endOffset,
			long length, int format, short version, long abbreviationOffset, byte pointerSize,
			int compUnitNumber, int language) {
		super(dwarfProgram, startOffset, endOffset, length, format, version, abbreviationOffset,
			pointerSize, compUnitNumber, startOffset, null);

		setCompileUnit(
			new DWARFCompileUnit("Mock Comp Unit", "Mock Comp Unit Producer", "Mock Comp Unit Dir",
				0, 0, language, DWARFIdentifierCase.DW_ID_case_insensitive, false, null));
		compUnitDIE = new DIECreator(DWARFTag.DW_TAG_compile_unit)
				.addString(DWARFAttribute.DW_AT_name, "MockCompUnit" + compUnitNumber)
				.create(this);
	}

	@Override
	public void readDIEs(List<DebugInfoEntry> dies, TaskMonitor unused_monitor) {
		dies.addAll(mockEntries);
	}

	public DebugInfoEntry getCompileUnitDIE() {
		return compUnitDIE;
	}

	public void addMockEntry(DebugInfoEntry die) {
		mockEntries.add(die);
	}

	public int getMockEntryCount() {
		return mockEntries.size();
	}

}
