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
package sarif;

import org.junit.Test;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramDiff;

public class MarkupSarifTest extends AbstractSarifTest {

	public MarkupSarifTest() {
		super();
	}

	@Test
	public void testExternalReferences() throws Exception {
		ReferenceManager refMgr = program.getReferenceManager();
		refMgr.addExternalReference(entry.add(100), "io.dll", "label", null, SourceType.USER_DEFINED, 0, RefType.DATA);

		refMgr.addExternalReference(entry.add(100), "foo.dll", "ABC", null, SourceType.ANALYSIS, 1, RefType.DATA);

		refMgr.addExternalReference(entry.add(500), "foo.dll", null, entry.add(4000), SourceType.IMPORTED, 2,
				RefType.READ_WRITE);

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
	}

	@Test
	public void testMemReference() throws Exception {
		ReferenceManager refMgr = program.getReferenceManager();
		Reference ref = refMgr.addMemoryReference(entry.add(512), entry.add(256), RefType.FLOW, SourceType.DEFAULT, 2);
		refMgr.setPrimary(ref, false);

		ref = refMgr.addMemoryReference(entry.add(784), entry.add(256), RefType.FLOW, SourceType.USER_DEFINED, -1);
		refMgr.setPrimary(ref, false);

		refMgr.addMemoryReference(entry.add(600), entry.add(256), RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 2);

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
	}
	
	@Test
    public void testOffsetReference() throws Exception {
		ReferenceManager refMgr = program.getReferenceManager();
		refMgr.addOffsetMemReference(entry.add(100), entry.add(600), false, 100,
			RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, 0);

		refMgr.addMemoryReference(entry.add(100), entry.add(1000), RefType.COMPUTED_JUMP,
			SourceType.USER_DEFINED, 0);

		refMgr.addMemoryReference(entry.add(100), entry.add(1005), RefType.COMPUTED_JUMP,
			SourceType.USER_DEFINED, -1);

		refMgr.removeAllReferencesFrom(entry.add(100));
		
		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
	}

}
