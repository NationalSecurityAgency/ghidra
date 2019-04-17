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

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 *
 * To change the template for this generated type comment go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 * 
 * 
 */
public class ExpandBlockDownModelTest extends AbstractGhidraHeadedIntegrationTest
		implements ChangeListener {
	private Program program;
	private PluginTool tool;
	private TestEnv env;
	private ExpandBlockModel model;
	private MemoryBlock block;

	/**
	 * Constructor for ExpandBlockDownModelTest.
	 * @param arg0
	 */
	public ExpandBlockDownModelTest() {
		super();
	}

	private Program buildProgram(String programName) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(programName, ProgramBuilder._TOY);
		builder.createMemory("test1", Long.toHexString(0x1001000), 0x6600);
		builder.createMemory("test2", Long.toHexString(0x1008000), 0x600);
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
		block = program.getMemory().getBlock(getAddr(0x1001000));
		model = new ExpandBlockDownModel(tool, program);
		model.setChangeListener(this);
		model.initialize(block);
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
	public void testSetUpModel() {

		assertEquals(getAddr(0x1001000), model.getStartAddress());
		assertEquals(getAddr(0x10075ff), model.getEndAddress());
		assertEquals(0x6600, model.getLength());
	}

	@Test
	public void testSetEndAddress() {
		model.setEndAddress(getAddr(0x1007700));
		assertEquals(0x6701, model.getLength());
		assertTrue(model.getMessage().length() == 0);
	}

	@Test
	public void testSetBadAddress() {
		model.setEndAddress(getAddr(0x1007000));
		assertTrue(model.getMessage().length() > 0);
	}

	@Test
	public void testSetLength() {
		model.setLength(0x7000);
		assertTrue(model.getMessage().length() == 0);
		assertEquals(getAddr(0x1007fff), model.getEndAddress());
	}

	@Test
	public void testSetBadLength() {
		model.setLength(-1);
		assertTrue(model.getMessage().length() > 0);

		model.setLength(0x7000);
		assertTrue(model.getMessage().length() == 0);

		model.setLength(0x500);
		assertTrue(model.getMessage().length() > 0);
	}

	@Test
	public void testExectute() {
		model.setLength(0x7000);
		assertTrue(model.execute());
		MemoryBlock newblock = program.getMemory().getBlock(getAddr(0x1001000));
		assertNotNull(newblock);
		assertEquals(getAddr(0x1007fff), newblock.getEnd());
	}

	@Test
	public void testOverlap() {
		model.setEndAddress(getAddr(0x1008010));
		assertTrue(!model.execute());
		assertTrue(model.getMessage().length() > 0);
	}

	@Test
	public void testNoChanges() {
		model.setLength(0x6600);
		assertTrue(model.execute());
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
