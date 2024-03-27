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

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;

import ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.IntArrayList;
import ghidra.util.datastruct.LongArrayList;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MockDWARFProgram extends DWARFProgram {

	private MockDWARFCompilationUnit currentCompUnit;
	private List<DebugInfoEntry> dies = new ArrayList<>();

	public MockDWARFProgram(Program program, DWARFImportOptions importOptions, TaskMonitor monitor)
			throws CancelledException, IOException, DWARFException {
		super(program, importOptions, monitor);
	}

	public MockDWARFProgram(Program program, DWARFImportOptions importOptions, TaskMonitor monitor,
			DWARFSectionProvider sectionProvider)
			throws CancelledException, IOException, DWARFException {
		super(program, importOptions, monitor, sectionProvider);
	}

	public MockDWARFCompilationUnit getCurrentCompUnit() {
		return currentCompUnit;
	}

	public MockDWARFCompilationUnit addCompUnit() {
		return addCompUnit(DWARFSourceLanguage.DW_LANG_C);
	}

	public MockDWARFCompilationUnit addCompUnit(int cuLang) {
		return addCompUnit(cuLang, 4 /* dwarf32 */);
	}

	public MockDWARFCompilationUnit addCompUnit(int cuLang, int dwarfIntSize) {
		if (currentCompUnit == null && !compUnitDieIndex.isEmpty()) {
			Assert.fail();
		}

		if (currentCompUnit != null) {
			compUnitDieIndex.put(dieOffsets.length - 1, currentCompUnit);
		}
		long start = compUnits.size() * 0x1000;
		currentCompUnit = new MockDWARFCompilationUnit(this, start, start + 0x1000, dwarfIntSize,
			(short) 4, (byte) 8, 0);
		compUnits.add(currentCompUnit);
		compUnitDieIndex.put(dieOffsets.length - 1, currentCompUnit);

		DebugInfoEntry compUnitRootDIE = new DIECreator(this, DWARFTag.DW_TAG_compile_unit)
				.addInt(DWARFAttribute.DW_AT_language, cuLang)
				.createRootDIE();
		try {
			currentCompUnit.init(compUnitRootDIE);
		}
		catch (IOException e) {
			fail();
		}

		return currentCompUnit;
	}

	public long getRelativeDIEOffset(int count) {
		int cuDIECount = currentCompUnit.incDIECount();
		return currentCompUnit.getStartOffset() + cuDIECount + count;
	}

	public DebugInfoEntry addDIE(DWARFAbbreviation abbr, DebugInfoEntry parent) {
		LongArrayList dieOffsetList = new LongArrayList(dieOffsets);
		IntArrayList siblingIndexList = new IntArrayList(siblingIndexes);
		IntArrayList parentIndexList = new IntArrayList(parentIndexes);

		int dieIndex = dieOffsetList.size();
		int cuDIECount = currentCompUnit.incDIECount();
		DebugInfoEntry die =
			new DebugInfoEntry(currentCompUnit, currentCompUnit.getStartOffset() + cuDIECount,
				dieIndex, abbr, new int[abbr.getAttributeCount()]);

		diesByOffset.put(die.getOffset(), die);
		dieOffsetList.add(die.getOffset());
		parentIndexList.add(parent != null ? parent.getIndex() : -1);
		siblingIndexList.add(dieIndex + 1);

		updateSiblingIndexes(siblingIndexList, parentIndexList, dieIndex);

		dieOffsets = dieOffsetList.toLongArray();
		siblingIndexes = siblingIndexList.toArray();
		parentIndexes = parentIndexList.toArray();

		dies.add(die);

		return die;
	}

	public void buildMockDIEIndexes() throws CancelledException, DWARFException {
		if (currentCompUnit == null) {
			return;
		}

		compUnitDieIndex.put(dieOffsets.length - 1, currentCompUnit);
		currentCompUnit = null;

		LongArrayList aggrTargets = new LongArrayList();
		for (DebugInfoEntry die : dies) {
			DIEAggregate diea = DIEAggregate.createSingle(die);
			for (DWARFAttribute attr : REF_ATTRS) {
				long refdOffset = diea.getUnsignedLong(attr, -1);
				if (refdOffset != -1) {
					aggrTargets.add(refdOffset);
				}
			}
		}
		indexDIEAggregates(aggrTargets, TaskMonitor.DUMMY); // after this point, DIEAggregates are functional
		indexDIEATypeRefs(TaskMonitor.DUMMY);

	}

}
