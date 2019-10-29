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
package ghidra.app.plugin.core.script;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.*;
import org.junit.experimental.categories.Category;

import generic.jar.ResourceFile;
import generic.test.category.NightlyCategory;
import ghidra.app.services.ProgramManager;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.test.*;

@Category(NightlyCategory.class)
public class WindowsResourceReferenceScriptTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private File script;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		ResourceFile resourceFile =
			Application.getModuleFile("Decompiler", "ghidra_scripts/WindowsResourceReference.java");

		script = resourceFile.getFile(true);
	}

	private void openProgram(Program program) {
		ProgramManager pm = env.getTool().getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
	}

	private void closeProgram() {
		ProgramManager pm = env.getTool().getService(ProgramManager.class);
		pm.closeProgram();
		waitForPostedSwingRunnables();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	/*
	 * Checks against known result set of addresses for use in regression testing.
	 * Checks each address location of created reference and checks
	 * that the correct format of address has been created to the resource
	 */
	@Test
	public void testWinmineNormalCases() throws Exception {
		Reference[] refs; //Array of mnemonic references
		RefType type; 	 //Type of reference
		Instruction inst;
		Boolean isAddr;

		Program program = env.getProgram("Winmine__XP.exe.gzf");
		openProgram(program);

		ScriptTaskListener scriptId = env.runScript(script);
		waitForScriptCompletion(scriptId, 65000);
		program.flushEvents();
		waitForPostedSwingRunnables();

		Listing listing = program.getListing();

		//Fill array with addresses of reference results
		Address[] winmineTestAddrs = propagateWinMineTestAddrs(program);

		for (Address winmineTestAddr : winmineTestAddrs) {
			inst = listing.getInstructionAt(winmineTestAddr);
			refs = inst.getMnemonicReferences();
			//Check a reference exists on the Mnemonic
			assertNotNull(refs);
			type = refs[0].getReferenceType();
			isAddr = refs[0].getToAddress().isMemoryAddress();
			//Check the reference is a real memory address
			assertTrue(isAddr);
			//Check the reference type created is of type DATA
			assertTrue(type.equals(RefType.DATA));
		}
		closeProgram();
	}

	@Test
	public void testMIPNormalCases() throws Exception {
		Reference[] refs; //Array of mnemonic references
		RefType type;    //Type of reference
		Boolean isAddr;
		Instruction inst;

		Program program = env.getProgram("mip.exe.gzf");
		openProgram(program);

		ScriptTaskListener scriptID = env.runScript(script);
		waitForScriptCompletion(scriptID, 60000);
		program.flushEvents();
		waitForPostedSwingRunnables();

		Listing listing = program.getListing();

		Address[] mipTestAddrs = propagateMIPTestAddrs(program);
		for (Address mipTestAddr : mipTestAddrs) {
			inst = listing.getInstructionAt(mipTestAddr);
			refs = inst.getMnemonicReferences();
			//Check a reference exists on the mnemonic
			assertNotNull(refs);
			type = refs[0].getReferenceType();
			isAddr = refs[0].getToAddress().isMemoryAddress();
			//check the reference is a real memory address
			assertTrue(isAddr);
			//check the reference type created is of type DATA
			assertTrue(type.equals(RefType.DATA));
		}

		closeProgram();
	}

	private Address addr(long offset, Program program) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/*
	 * Creates and returns the known result set to check against for use 
	 * in regression testing
	 */
	protected Address[] propagateWinMineTestAddrs(Program pgm) {
		Address[] winmineTestAddrs = { addr(0x01001b99, pgm), addr(0x01001bc2, pgm),
			addr(0x01001b5e, pgm), addr(0x010022c2, pgm), addr(0x01002243, pgm),
			addr(0x01003d52, pgm), addr(0x010022ac, pgm), addr(0x01002334, pgm),
			addr(0x01001f3b, pgm), addr(0x0100398f, pgm), addr(0x01003ade, pgm),
			addr(0x01003aec, pgm), addr(0x01003ad0, pgm), addr(0x010039c5, pgm),
			addr(0x01003d45, pgm), addr(0x0100385b, pgm), addr(0x01003d36, pgm),
			addr(0x01003920, pgm), addr(0x0100390e, pgm) };

		return winmineTestAddrs;
	}

	protected Address[] propagateMIPTestAddrs(Program pgm) {
		Address[] mipTestAddrs =

			{ addr(0x1400172c7L, pgm), addr(0x14005282dL, pgm), addr(0x14005276cL, pgm),
				addr(0x1400523baL, pgm), addr(0x14004ca38L, pgm), addr(0x14003d855L, pgm),
				addr(0x14001a964L, pgm), addr(0x14001846fL, pgm), addr(0x140025c87L, pgm) };

		return mipTestAddrs;
	}

}
