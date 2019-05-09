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
package ghidra.app.plugin.core.decompile;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.test.ClassicSampleX86ProgramBuilder;

public class DecompilerNavigationTest extends AbstractDecompilerTest {

	@Before
	@Override
	public void setUp() throws Exception {
		super.setUp();

		CodeViewerProvider cbProvider = codeBrowser.getProvider();
		tool.showComponentProvider(cbProvider, true);
	}

	@Override
	protected Program getProgram() throws Exception {
		return buildProgram();
	}

	private Program buildProgram() throws Exception {
		ClassicSampleX86ProgramBuilder builder =
			new ClassicSampleX86ProgramBuilder("notepad", false, this);

		// need a default label at 01002cf0, so make up a reference
		builder.createMemoryReference("01002ce5", "01002cf0", RefType.FALL_THROUGH,
			SourceType.ANALYSIS);

		return builder.getProgram();
	}

	@Test
	public void testNavigation_ExternalEventDoesNotTriggerNavigation() {

		//
		// Test to make sure that external ProgramLocationEvent notifications to not trigger 
		// the Decompiler to broadcast a new event.   Setup a tool with the Listing and 
		// the Decompiler open.  Then, navigate in the Listing and verify the address does not
		// move.  (This is somewhat subject to the Code Unit at the address in how the 
		// Decompiler itself responds to the incoming event.)
		//

		// very specific location within the instruction that is known to affect how the
		// decompiler responds
		String operandPrefix = "dword ptr [EBP + ";
		String operandReferenceName = "destStr]";
		OperandFieldLocation operandLocation = new OperandFieldLocation(program, addr("0100416c"),
			null, addr("0x8"), operandPrefix + operandReferenceName, 1, 9);
		codeBrowser.goTo(operandLocation);
		waitForSwing();

		ProgramLocation currentLocation = codeBrowser.getCurrentLocation();
		assertTrue(currentLocation instanceof OperandFieldLocation);
		assertEquals(operandLocation.getAddress(), currentLocation.getAddress());
	}
}
