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
import ghidra.program.util.ProgramDiff;

public class ProgramTreeSarifTest extends AbstractSarifTest {

	public ProgramTreeSarifTest() {
		super();
	}

	@Test
	public void testProgamTrees() throws Exception {
		block.putBytes(entry, asm, 0, asm.length);
		
		builder.createProgramTree("Main Tree");
		builder.getOrCreateModule("Main Tree", "A");
		builder.getOrCreateModule("Main Tree", "A.B");
		builder.createProgramTree("Tree One");
		builder.createProgramTree("Tree Two");
		builder.createProgramTree("Tree Three");
		builder.getOrCreateModule("Tree Three", "Strings");
		
		builder.createFragment("Main Tree", "A", "a", "0x1002000", "0x1002002");
		builder.createFragment("Main Tree", "A", "b", "0x1002003", "0x1002005");
		builder.createFragment("Main Tree", "A", "c", "0x1002010", "0x1002020");
		builder.createFragment("Main Tree", "A.B", "d", "0x1002024", "0x1002026");
		builder.createFragment("Main Tree", "A.B", "e", "0x1002026", "0x1002028");
		builder.createFragment("Main Tree", "A.B", "f", "0x1002028", "0x100202a");

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

}
