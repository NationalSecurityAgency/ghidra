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
package ghidra.machinelearning.functionfinding;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FunctionStartRFParamsProgramBasedTest extends AbstractProgramBasedTest {

	private final static String BASE_ADDRESS = "0x10000";
	private final static String ADD_R0_R1_R2_ARM = "02 00 81 e0";
	private final static String BX_LR_ARM = "1e ff 2f e1";

	private final static String ADD_R0_R1_THUMB = "08 44";
	private final static String BX_LR_THUMB = "70 47";

	@Before
	public void setUp() throws Exception {
		initialize();
	}

	@Override
	protected Program getProgram() throws Exception {
		return buildProgram();
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("DataGatheringUtilsTest", ProgramBuilder._ARM);
		MemoryBlock block = builder.createMemory(".text", BASE_ADDRESS, 0x100);
		builder.setExecute(block, true);
		//undefined
		builder.setBytes(BASE_ADDRESS, "00 01 02 03", false);

		//small arm function
		builder.setBytes("0x10004", ADD_R0_R1_R2_ARM, true);
		builder.setBytes("0x10008", BX_LR_ARM, true);
		builder.createFunction("0x10004");

		//larger arm function
		builder.setBytes("0x1000c", ADD_R0_R1_R2_ARM, true);
		builder.setBytes("0x10010", ADD_R0_R1_R2_ARM, true);
		builder.setBytes("0x10014", ADD_R0_R1_R2_ARM, true);
		builder.setBytes("0x10018", ADD_R0_R1_R2_ARM, true);
		builder.setBytes("0x1001c", BX_LR_ARM, true);
		builder.createFunction("0x1000c");

		builder.setRegisterValue("TMode", "0x10020", "0x10036", 1);

		//small thumb function
		builder.setBytes("0x10020", ADD_R0_R1_THUMB, true);
		builder.setBytes("0x10022", BX_LR_THUMB, true);
		builder.createFunction("0x10020");

		//larger thumb function
		builder.setBytes("0x10024", ADD_R0_R1_THUMB, true);
		builder.setBytes("0x10026", ADD_R0_R1_THUMB, true);
		builder.setBytes("0x10028", ADD_R0_R1_THUMB, true);
		builder.setBytes("0x1002a", ADD_R0_R1_THUMB, true);
		builder.setBytes("0x1002c", ADD_R0_R1_THUMB, true);
		builder.setBytes("0x1002e", ADD_R0_R1_THUMB, true);
		builder.setBytes("0x10030", ADD_R0_R1_THUMB, true);
		builder.setBytes("0x10032", BX_LR_THUMB, true);
		builder.createFunction("0x10024");

		return builder.getProgram();
	}

	@Test
	public void testCheckContextRegisters() {
		FunctionStartRFParams params = new FunctionStartRFParams(program);
		Address armFunc = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000c);
		Address thumbFunc =
			program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10020);
		assertTrue(params.isContextCompatible(armFunc));
		assertTrue(params.isContextCompatible(thumbFunc));
		params.setRegistersAndValues("TMode=1");
		assertFalse(params.isContextCompatible(armFunc));
		assertTrue(params.isContextCompatible(thumbFunc));
	}

	@Test
	public void testComputeEntriesAndInteriors() throws CancelledException {

		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();

		Address smallArmEntry = defaultSpace.getAddress(0x10004);
		//instruction alignment for the processor is 2, even in ARM mode
		//so we need to adjust the arm interiors
		AddressSet smallArmInterior = new AddressSet(defaultSpace.getAddress(0x10008));
		smallArmInterior.add(defaultSpace.getAddress(0x10006));
		smallArmInterior.add(defaultSpace.getAddress(0x1000a));

		Address largeArmEntry = defaultSpace.getAddress(0x1000c);
		AddressSet largeArmInterior = new AddressSet(defaultSpace.getAddress(0x10010));
		largeArmInterior.add(defaultSpace.getAddress(0x1000e));
		largeArmInterior.add(defaultSpace.getAddress(0x10012));
		largeArmInterior.add(defaultSpace.getAddress(0x10014));
		largeArmInterior.add(defaultSpace.getAddress(0x10016));
		largeArmInterior.add(defaultSpace.getAddress(0x10018));
		largeArmInterior.add(defaultSpace.getAddress(0x1001a));
		largeArmInterior.add(defaultSpace.getAddress(0x1001c));
		largeArmInterior.add(defaultSpace.getAddress(0x1001e));

		Address smallThumbEntry = defaultSpace.getAddress(0x10020);
		AddressSet smallThumbInterior = new AddressSet(defaultSpace.getAddress(0x10022));

		Address largeThumbEntry = defaultSpace.getAddress(0x10024);
		AddressSet largeThumbInterior = new AddressSet(defaultSpace.getAddress(0x10026));
		largeThumbInterior.add(defaultSpace.getAddress(0x10028));
		largeThumbInterior.add(defaultSpace.getAddress(0x1002a));
		largeThumbInterior.add(defaultSpace.getAddress(0x1002c));
		largeThumbInterior.add(defaultSpace.getAddress(0x1002e));
		largeThumbInterior.add(defaultSpace.getAddress(0x10030));
		largeThumbInterior.add(defaultSpace.getAddress(0x10032));

		FunctionStartRFParams params = new FunctionStartRFParams(program);
		params.computeFuncEntriesAndInteriors(TaskMonitor.DUMMY);
		AddressSet entries = params.getFuncEntries();
		AddressSet interiors = params.getFuncInteriors();
		assertTrue(!entries.intersects(interiors));
		assertEquals(4, entries.getNumAddresses());
		assertTrue(entries.contains(smallArmEntry));
		assertTrue(entries.contains(largeArmEntry));
		assertTrue(entries.contains(smallThumbEntry));
		assertTrue(entries.contains(largeThumbEntry));

		assertEquals(
			smallThumbInterior.getNumAddresses() + largeThumbInterior.getNumAddresses() +
				smallArmInterior.getNumAddresses() + largeArmInterior.getNumAddresses(),
			interiors.getNumAddresses());
		assertTrue(interiors.contains(smallThumbInterior.union(largeThumbInterior)
				.union(smallArmInterior)
				.union(largeArmInterior)));

		params = new FunctionStartRFParams(program);
		params.setMinFuncSize(10);
		params.setRegistersAndValues("TMode=0");
		params.computeFuncEntriesAndInteriors(TaskMonitor.DUMMY);
		entries = params.getFuncEntries();
		interiors = params.getFuncInteriors();
		assertTrue(!entries.intersects(interiors));
		assertEquals(1, entries.getNumAddresses());
		assertTrue(entries.contains(largeArmEntry));

		assertTrue(interiors.contains(largeArmInterior));
		assertEquals(interiors.getNumAddresses(), largeArmInterior.getNumAddresses());

		params = new FunctionStartRFParams(program);
		params.setMinFuncSize(10);
		params.setRegistersAndValues("TMode=1");
		params.computeFuncEntriesAndInteriors(TaskMonitor.DUMMY);
		entries = params.getFuncEntries();
		interiors = params.getFuncInteriors();
		assertTrue(!entries.intersects(interiors));
		assertEquals(1, entries.getNumAddresses());
		assertTrue(entries.contains(largeThumbEntry));

		assertTrue(interiors.contains(largeThumbInterior));
		assertEquals(interiors.getNumAddresses(), largeThumbInterior.getNumAddresses());

	}

}
