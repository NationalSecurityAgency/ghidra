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
package ghidra.program.util;

import static org.junit.Assert.assertEquals;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.CancelledException;

public class AbstractProgramDiffTest extends AbstractGhidraHeadedIntegrationTest {

	protected ProgramDiff programDiff;
	protected ClassicSampleX86ProgramBuilder programBuilder1;
	protected ClassicSampleX86ProgramBuilder programBuilder2;
	protected Program p1;
	protected Program p2;

	protected Address addr(int offset) {
		AddressSpace space = p1.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(offset);
	}

	protected Address addr(Program program, int offset) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(offset);
	}

	protected Address addr(Program program, String addrString) {
		return program.getAddressFactory().getAddress(addrString);
	}

	protected void checkNoCommentDifference() throws Exception {
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.COMMENT_DIFFS));
		AddressSet as = new AddressSet();
		AddressSetView diffAs = programDiff.getDifferences(programDiff.getFilter(), null);
		assertEquals(as, diffAs);
	}

	protected void checkDiff(AddressSet expectedDiffs, int diffType)
			throws ProgramConflictException, CancelledException {
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(diffType));
		assertEquals(expectedDiffs, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	protected void createDataReference(Program pgm, Address fromAddr, Address toAddr) {
		ReferenceManager refMgr = pgm.getReferenceManager();
		refMgr.addMemoryReference(fromAddr, toAddr, RefType.DATA, SourceType.USER_DEFINED, 0);
	}

	protected Function getFunction(Program program, String address) {
		Address addr = addr(program, address);
		return program.getFunctionManager().getFunctionAt(addr);
	}

}
