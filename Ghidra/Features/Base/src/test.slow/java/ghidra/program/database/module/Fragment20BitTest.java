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
package ghidra.program.database.module;

import static org.junit.Assert.assertTrue;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitorAdapter;

/**
 *
 * To change the template for this generated type comment go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 * 
 * 
 * 
 */
public class Fragment20BitTest extends AbstractGhidraHeadedIntegrationTest {
	private ProgramDB program;
	private SegmentedAddressSpace space;
	private int transactionID;
	private ProgramModule root;
	private TestEnv env;

	public Fragment20BitTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		program =
			createDefaultProgram(testName.getMethodName(), ProgramBuilder._X86_16_REAL_MODE, this);
		space = (SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		transactionID = program.startTransaction("Test");
		root = program.getListing().createRootModule("MyTree");
		addBlocks();
	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, false);
		env.dispose();
	}

	@Test
    public void testMoveCodeUnit() throws Exception {
		ProgramFragment frag = root.createFragment("testFrag");
		frag.move(addr("0d43:0000"), addr("0000:e517"));

		ProgramFragment sf = root.createFragment("SingleCU");
		sf.move(addr("0000:e517"), addr("0000:e517"));

		assertTrue(sf.contains(addr("0000:e517")));
	}

	private void addBlocks() throws Exception {
		Memory mem = program.getMemory();

		Address start = addr("0000:0000");
		mem.createInitializedBlock("stdproc.c", start, 0x5EDA, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		start = addr("05ee:0000");
		mem.createInitializedBlock("scada.c", start, 0x5FAA, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		start = addr("0be9:0000");
		mem.createInitializedBlock("cseg03", start, 0x2A6, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		start = addr("0c14:0000");
		mem.createInitializedBlock("cseg04", start, 0xF04, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		start = addr("0d05:0000");
		mem.createInitializedBlock("cseg05", start, 0x3E0, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		start = addr("0d43:0000");
		mem.createInitializedBlock("cseg06", start, 0x10E8, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

	}

	private Address addr(String str) throws Exception {
		return space.getAddress(str);
	}
}
