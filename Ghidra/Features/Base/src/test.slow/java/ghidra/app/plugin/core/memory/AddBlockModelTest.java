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
package ghidra.app.plugin.core.memory;

import static org.junit.Assert.*;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.junit.*;

import ghidra.app.plugin.core.memory.AddBlockModel.InitializedType;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 *
 * Test the add memory block model. 
 * 
 */
public class AddBlockModelTest extends AbstractGhidraHeadedIntegrationTest
		implements ChangeListener {
	private Program program;
	private PluginTool tool;
	private TestEnv env;
	private AddBlockModel model;

	/**
	 * Constructor for AddBlockModelTest.
	 * @param name
	 */
	public AddBlockModelTest() {
		super();
	}

	private Program buildProgram(String programName) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(programName, ProgramBuilder._TOY);
		builder.createMemory(".data", Long.toHexString(0x1001000), 0x6000);
		return builder.getProgram();
	}

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		program = buildProgram("notepad");
		model = new AddBlockModel(tool, program);
		model.setChangeListener(this);
	}

	/*
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		env.release(program);
		env.dispose();
	}

	@Test
	public void testSetFieldsForInitializedBlock() {
		model.setBlockName(".test");
		assertTrue(!model.isValidInfo());

		model.setStartAddress(getAddr(0x100));
		assertTrue(!model.isValidInfo());

		model.setLength(100);
		assertTrue(model.isValidInfo());

		model.setBlockType(MemoryBlockType.DEFAULT);
		assertTrue(model.isValidInfo());

		model.setInitialValue(0xa);
		assertTrue(model.isValidInfo());
	}

	@Test
	public void testSetFieldsForUninitializedBlock() {
		model.setBlockName(".test");
		assertTrue(!model.isValidInfo());

		model.setStartAddress(getAddr(0x200));
		assertTrue(!model.isValidInfo());

		model.setLength(100);
		assertTrue(model.isValidInfo());

		model.setBlockType(MemoryBlockType.DEFAULT);
		assertTrue(model.isValidInfo());

	}

	@Test
	public void testSetFieldsForBitBlock() {
		model.setBlockName(".test");
		assertTrue(!model.isValidInfo());

		model.setStartAddress(getAddr(0x200));
		assertTrue(!model.isValidInfo());

		model.setLength(100);
		assertTrue(model.isValidInfo());

		model.setBlockType(MemoryBlockType.BIT_MAPPED);
		assertTrue(!model.isValidInfo());

		model.setBaseAddress(getAddr(0x2000));
		assertTrue(model.isValidInfo());
	}

	@Test
	public void testSetFieldsForOverlayBlock() {
		model.setBlockName(".test");
		assertTrue(!model.isValidInfo());

		model.setStartAddress(getAddr(0x200));
		assertTrue(!model.isValidInfo());

		model.setLength(100);
		assertTrue(model.isValidInfo());

		model.setBlockType(MemoryBlockType.DEFAULT);
		assertTrue(model.isValidInfo());

		model.setOverlay(true);
		assertTrue(model.isValidInfo());

		model.setBaseAddress(getAddr(0x2000));
		assertTrue(model.isValidInfo());
	}

	@Test
	public void testBadName() {
		model.setBlockName(">/== test");
		assertTrue(!model.isValidInfo());
		assertTrue(model.getMessage().length() > 0);
	}

	@Test
	public void testExecute() throws Exception {
		model.setBlockName(".test");
		model.setStartAddress(getAddr(0x100));
		model.setLength(100);
		model.setBlockType(MemoryBlockType.DEFAULT);
		model.setInitializedType(InitializedType.INITIALIZED_FROM_VALUE);
		model.setInitialValue(0xa);
		model.setComment("Test");
		model.setRead(true);
		model.setWrite(true);
		model.setExecute(true);
		assertTrue(model.execute());
		MemoryBlock block = program.getMemory().getBlock(getAddr(0x100));
		assertNotNull(block);
		assertEquals((byte) 0xa, block.getByte(getAddr(0x100)));
	}

	@Test
	public void testCreateOverlayBlock() throws Exception {

		model.setBlockName(".test");
		model.setStartAddress(getAddr(0x100));
		model.setLength(100);
		model.setBlockType(MemoryBlockType.DEFAULT);
		model.setOverlay(true);
		model.setInitializedType(InitializedType.INITIALIZED_FROM_VALUE);
		model.setInitialValue(0xa);
		assertTrue(model.execute());
		MemoryBlock block = null;
		AddressSpace[] spaces = program.getAddressFactory().getAddressSpaces();
		AddressSpace ovSpace = null;
		for (AddressSpace space : spaces) {
			if (space.isOverlaySpace()) {
				ovSpace = space;
				Address blockAddr = space.getAddress(0x100);
				block = program.getMemory().getBlock(blockAddr);
				break;
			}
		}
		assertNotNull(block);
		assertEquals((byte) 0xa, block.getByte(ovSpace.getAddress(0x100)));
	}

	@Test
	public void testCreateOverlayBlock2() throws Exception {

		model.setBlockName(".test");
		model.setStartAddress(getAddr(0x01001000));
		model.setLength(100);
		model.setBlockType(MemoryBlockType.DEFAULT);
		model.setOverlay(true);
		model.setInitializedType(InitializedType.INITIALIZED_FROM_VALUE);
		model.setInitialValue(0xa);
		assertTrue(model.execute());
		MemoryBlock block = null;
		AddressSpace[] spaces = program.getAddressFactory().getAddressSpaces();
		AddressSpace ovSpace = null;
		for (AddressSpace space : spaces) {
			if (space.isOverlaySpace()) {
				ovSpace = space;
				Address blockAddr = space.getAddress(0x1001000);
				block = program.getMemory().getBlock(blockAddr);
				break;
			}
		}
		assertNotNull(block);
		assertEquals((byte) 0xa, block.getByte(ovSpace.getAddress(0x1001000)));
	}

	@Test
	public void testCreateBitMappedBlock() throws Exception {
		model.setBlockName(".test");
		model.setStartAddress(getAddr(0x100));
		model.setLength(100);
		model.setBlockType(MemoryBlockType.BIT_MAPPED);
		assertEquals(InitializedType.UNITIALIZED, model.getInitializedType());
		model.setBaseAddress(getAddr(0x2000));

		assertTrue(model.execute());
		MemoryBlock block = program.getMemory().getBlock(getAddr(0x100));
		assertNotNull(block);
		assertEquals(MemoryBlockType.BIT_MAPPED, block.getType());
	}

	@Test
	public void testCreateByteMappedBlock() throws Exception {
		model.setBlockName(".test");
		model.setStartAddress(getAddr(0x100));
		model.setLength(100);
		model.setBlockType(MemoryBlockType.BYTE_MAPPED);
		assertEquals(InitializedType.UNITIALIZED, model.getInitializedType());
		model.setBaseAddress(getAddr(0x2000));

		assertTrue(model.execute());
		MemoryBlock block = program.getMemory().getBlock(getAddr(0x100));
		assertNotNull(block);
		assertEquals(MemoryBlockType.BYTE_MAPPED, block.getType());

	}

	@Test
	public void testInvalidNameSetting() {
		model.setBlockName("");
		assertTrue(!model.isValidInfo());
		assertTrue(model.getMessage().length() > 0);
	}

	@Test
	public void testDuplicateName() {
		model.setBlockName(".data");
		model.setOverlay(false);
		model.setStartAddress(getAddr(0x100));
		model.setLength(100);
		model.setBlockType(MemoryBlockType.DEFAULT);
		model.setInitialValue(0xa);
		assertTrue(model.execute());
	}

	@Test
	public void testStartAddress() throws Exception {

		int transactionID = program.startTransaction("test");
		try {
			program.setImageBase(getAddr(0x3000100), true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		model = new AddBlockModel(tool, program);
		assertEquals(program.getImageBase(), model.getStartAddress());
	}

	/**
	 * @see javax.swing.event.ChangeListener#stateChanged(javax.swing.event.ChangeEvent)
	 */
	@Override
	public void stateChanged(ChangeEvent e) {
	}

	private Address getAddr(int offset) {
		return program.getMinAddress().getNewAddress(offset);
	}
}
