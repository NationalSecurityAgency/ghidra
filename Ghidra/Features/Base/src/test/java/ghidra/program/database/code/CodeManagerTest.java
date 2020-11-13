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
package ghidra.program.database.code;

import static org.junit.Assert.*;

import java.awt.Color;
import java.math.BigInteger;
import java.util.Iterator;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.util.PropertyMap;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.Lock;
import ghidra.util.SaveableColor;
import ghidra.util.exception.NoValueException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Test the code manager portion of listing.
 *
 *
 */
public class CodeManagerTest extends AbstractGenericTest {

	private ToyProgramBuilder builder;

	private Listing listing;
	private AddressSpace space;
	private Program program;
	private Memory mem;
	private int transactionID;

	/**
	 * Constructor for CodeManagerTest.
	 * @param arg0
	 */
	public CodeManagerTest() {
		super();
	}

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {

		builder = new ToyProgramBuilder("Test", true, this);
		builder.createMemory("B1", "1000", 0x2000);

		program = builder.getProgram();

		space = program.getAddressFactory().getDefaultAddressSpace();
		listing = program.getListing();
		mem = program.getMemory();
		transactionID = program.startTransaction("Test");

	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	@Test
	public void testCreateInstruction() throws Exception {

		for (int i = 0; i < 0x80; i++) {
			builder.addBytesFallthrough(0x1000);
		}

		parseStatic(addr(0x1000), addr(0x10FF));
		assertEquals(0x80, listing.getNumInstructions());

		Instruction inst = listing.getInstructionAt(addr(0x1010));
		assertEquals(addr(0x1010), inst.getMinAddress());
		assertEquals("imm r0,#0x0", inst.toString());

	}

	@Test
	public void testInstruction() throws Exception {

		builder.addBytesBranch(0x2000, 0x2010);
		builder.addBytesReturn(0x2002);
		parseStatic(addr(0x2000), addr(0x2003));

		Instruction inst = listing.getInstructionAt(addr(0x2000));
		assertNotNull(inst);
		assertEquals("br", inst.getMnemonicString());
		assertEquals(1, inst.getNumOperands());
		assertEquals(addr(0x2010), inst.getAddress(0));

		try {
			listing.createData(addr(0x2000), ByteDataType.dataType);
			Assert.fail("Expected CodeUnitInsertionException");
		}
		catch (CodeUnitInsertionException e) {
			// expected
		}

		try {// should not be able to modify bytes where instruction exists
			program.getMemory().setByte(addr(0x2001), (byte) 0x12);
			Assert.fail("Expected MemoryAccessException");
		}
		catch (MemoryAccessException e) {
			// expected
		}

		// verify context change not permitted where instruction exists
		ProgramContext programContext = program.getProgramContext();
		try {
			programContext.setValue(programContext.getBaseContextRegister(), addr(0x1f00),
				addr(0x2100), BigInteger.ONE);
			Assert.fail("Expected ContextChangeException");
		}
		catch (ContextChangeException e) {
			// expected
		}
		programContext.setValue(programContext.getBaseContextRegister(), addr(0x1f00), addr(0x1fff),
			BigInteger.ONE);

		assertTrue(!inst.isFallThroughOverridden());
		assertEquals(FlowOverride.NONE, inst.getFlowOverride());
		assertEquals(RefType.UNCONDITIONAL_JUMP, inst.getFlowType());

		PcodeOp[] pcodeOps = inst.getPcode(true);
		assertEquals(1, pcodeOps.length);
		assertEquals(PcodeOp.BRANCH, pcodeOps[0].getOpcode());

		inst.setFlowOverride(FlowOverride.CALL_RETURN);

		assertEquals(FlowOverride.CALL_RETURN, inst.getFlowOverride());
		assertEquals(RefType.CALL_TERMINATOR, inst.getFlowType());

		pcodeOps = inst.getPcode(true);
		assertEquals(2, pcodeOps.length);
		assertEquals(PcodeOp.CALL, pcodeOps[0].getOpcode());
		assertEquals(PcodeOp.RETURN, pcodeOps[1].getOpcode());
	}

	@Test
	public void testCodeUnitComments() throws Exception {

		builder.addBytesBranch(0x2000, 0x2010);
		builder.addBytesReturn(0x2002);
		parseStatic(addr(0x2000), addr(0x2003));

		CodeUnit cu = listing.getCodeUnitAt(addr(0x2000));
		cu.setComment(CodeUnit.EOL_COMMENT, "eol comment");
		cu.setComment(CodeUnit.PLATE_COMMENT, "plate comment");

		cu = listing.getCodeUnitAt(addr(0x2000));
		String comment = cu.getComment(CodeUnit.EOL_COMMENT);
		assertNotNull(comment);
		assertEquals("eol comment", comment);
		comment = cu.getComment(CodeUnit.PLATE_COMMENT);
		assertNotNull(comment);
		assertEquals("plate comment", comment);
	}

	@Test
	public void testGetCodeUnitAfter() throws Exception {

		builder.addBytesBranch(0x2000, 0x2010);
		builder.addBytesReturn(0x2002);
		parseStatic(addr(0x2000), addr(0x2003));

		listing.createData(addr(0x2006), WordDataType.dataType);

		CodeUnit cu = listing.getCodeUnitAfter(addr(0x2000));
		assertTrue(cu instanceof Instruction);
		assertEquals(addr(0x2002), cu.getMinAddress());
		assertEquals("ret", cu.toString());

		cu = listing.getCodeUnitAfter(addr(0x2001));
		assertTrue(cu instanceof Instruction);
		assertEquals(addr(0x2002), cu.getMinAddress());
		assertEquals("ret", cu.toString());

		cu = listing.getCodeUnitAfter(addr(0x2002));
		assertTrue(cu instanceof Data);
		assertEquals(addr(0x2004), cu.getMinAddress());
		assertEquals("?? 00h", cu.toString());

		cu = listing.getCodeUnitAfter(addr(0x2005));
		assertTrue(cu instanceof Data);
		assertEquals(addr(0x2006), cu.getMinAddress());
		assertEquals("dw 0h", cu.toString());

	}

	@Test
	public void testGetCodeUnitBefore() throws Exception {

		builder.addBytesBranch(0x2000, 0x2010);
		builder.addBytesReturn(0x2002);
		parseStatic(addr(0x2000), addr(0x2003));

		listing.createData(addr(0x2006), WordDataType.dataType);

		CodeUnit cu = listing.getCodeUnitBefore(addr(0x2008));
		assertTrue(cu instanceof Data);
		assertEquals(addr(0x2006), cu.getMinAddress());
		assertEquals("dw 0h", cu.toString());

		cu = listing.getCodeUnitBefore(addr(0x2006));
		assertTrue(cu instanceof Data);
		assertEquals(addr(0x2005), cu.getMinAddress());
		assertEquals("?? 00h", cu.toString());

		cu = listing.getCodeUnitBefore(addr(0x2004));
		assertTrue(cu instanceof Instruction);
		assertEquals(addr(0x2002), cu.getMinAddress());
		assertEquals("ret", cu.toString());

		cu = listing.getCodeUnitBefore(addr(0x2003));
		assertTrue(cu instanceof Instruction);
		assertEquals(addr(0x2002), cu.getMinAddress());
		assertEquals("ret", cu.toString());

		cu = listing.getCodeUnitBefore(addr(0x2002));
		assertTrue(cu instanceof Instruction);
		assertEquals(addr(0x2000), cu.getMinAddress());
		assertEquals("br 0x00002010", cu.toString());
	}

	@Test
	public void testGetInstructionAfter() throws Exception {

		listing.createData(addr(0x1f00), WordDataType.dataType);

		builder.addBytesBranch(0x2000, 0x2010);
		builder.addBytesReturn(0x2002);
		parseStatic(addr(0x2000), addr(0x2003));

		listing.createData(addr(0x2006), WordDataType.dataType);

		Instruction inst = listing.getInstructionAfter(addr(0x1100));
		assertNotNull(inst);
		assertEquals(addr(0x2000), inst.getMinAddress());

		inst = listing.getInstructionAfter(addr(0x2000));
		assertNotNull(inst);
		assertEquals(addr(0x2002), inst.getMinAddress());

		inst = listing.getInstructionAfter(addr(0x2002));
		assertNull(inst);
	}

	@Test
	public void testGetInstructionBefore() throws Exception {

		listing.createData(addr(0x1f00), WordDataType.dataType);

		builder.addBytesBranch(0x2000, 0x2010);
		builder.addBytesReturn(0x2002);
		parseStatic(addr(0x2000), addr(0x2003));

		listing.createData(addr(0x2006), WordDataType.dataType);

		Instruction inst = listing.getInstructionBefore(addr(0x2100));
		assertNotNull(inst);
		assertEquals(addr(0x2002), inst.getMinAddress());

		inst = listing.getInstructionBefore(addr(0x2002));
		assertNotNull(inst);
		assertEquals(addr(0x2000), inst.getMinAddress());

		inst = listing.getInstructionBefore(addr(0x2000));
		assertNull(inst);

	}

	@Test
	public void testClear() throws Exception {

		listing.createData(addr(0x1f00), WordDataType.dataType);

		builder.addBytesBranch(0x2000, 0x2010);
		builder.addBytesReturn(0x2002);
		parseStatic(addr(0x2000), addr(0x2003));

		listing.createData(addr(0x2006), WordDataType.dataType);

		listing.createData(addr(0x2020), new StructureDataType("struct_1", 0x20));

		for (int i = 0; i < 100; i++) {
			listing.createData(addr(0x2040 + i), ByteDataType.dataType);
		}

		ProgramContext programContext = program.getProgramContext();
		programContext.setValue(programContext.getBaseContextRegister(), addr(0x1f00), addr(0x1fff),
			BigInteger.ONE);

		listing.clearCodeUnits(addr(0x1100), addr(0x2001), false);

		assertNull(listing.getInstructionContaining(addr(0x2001)));
		assertNull(listing.getDefinedDataAt(addr(0x1f00)));

		Instruction inst = listing.getInstructionAfter(addr(0x1000));
		assertNotNull(inst);
		assertEquals(addr(0x2002), inst.getMinAddress());

		Data data = listing.getDefinedDataAfter(addr(0x1f00));
		assertNotNull(data);
		assertEquals(addr(0x2006), data.getMinAddress());

		assertEquals(BigInteger.ONE,
			programContext.getValue(programContext.getBaseContextRegister(), addr(0x1f80), false));

		listing.clearCodeUnits(addr(0x2010), addr(0x2fff), false);

		assertNull(listing.getDefinedDataAfter(addr(0x2010)));

		assertNull(listing.getDefinedDataAt(addr(0x2020)));
		for (int i = 0; i < 1000; i++) {
			assertNull(listing.getDefinedDataAt(addr(0x2040 + i)));
		}
	}

	@Test
	public void testClearComments() throws Exception {

		builder.addBytesBranch(0x1000, 0x1010);
		builder.addBytesReturn(0x1002);
		parseStatic(addr(0x1000), addr(0x1003));

		listing.createData(addr(0x1f00), WordDataType.dataType);

		builder.addBytesBranch(0x2000, 0x2010);
		builder.addBytesReturn(0x2002);
		parseStatic(addr(0x2000), addr(0x2003));

		listing.createData(addr(0x2006), WordDataType.dataType);

		InstructionIterator iter = listing.getInstructions(true);
		while (iter.hasNext()) {
			Instruction inst = iter.next();
			inst.setComment(CodeUnit.PRE_COMMENT, "pre comment");
			inst.setComment(CodeUnit.EOL_COMMENT, "eol comment");

			assertEquals("pre comment", inst.getComment(CodeUnit.PRE_COMMENT));
			assertEquals("eol comment", inst.getComment(CodeUnit.EOL_COMMENT));
		}

		Instruction inst = listing.getInstructionAt(addr(0x2000));
		assertEquals("pre comment", inst.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("eol comment", inst.getComment(CodeUnit.EOL_COMMENT));

		listing.clearComments(addr(0x2000), addr(0x2100));

		inst = listing.getInstructionAfter(addr(0x2000));
		assertNull(inst.getComment(CodeUnit.PRE_COMMENT));
		assertNull(inst.getComment(CodeUnit.EOL_COMMENT));

		inst = listing.getInstructionAt(addr(0x2000));
		assertNull(inst.getComment(CodeUnit.PRE_COMMENT));
		assertNull(inst.getComment(CodeUnit.EOL_COMMENT));

		inst = listing.getInstructionBefore(addr(0x2000));
		assertEquals("pre comment", inst.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("eol comment", inst.getComment(CodeUnit.EOL_COMMENT));
	}

	@Test
	public void testGetInstructionContaining() throws Exception {

		listing.createData(addr(0x1f00), WordDataType.dataType);

		builder.addBytesBranch(0x2000, 0x2010);
		builder.addBytesReturn(0x2002);
		parseStatic(addr(0x2000), addr(0x2003));

		listing.createData(addr(0x2006), WordDataType.dataType);

		Instruction inst = listing.getInstructionContaining(addr(0x2001));
		assertNotNull(inst);
		assertEquals(addr(0x2000), inst.getMinAddress());
		assertEquals(addr(0x2001), inst.getMaxAddress());

		inst = listing.getInstructionContaining(addr(0x2002));
		assertNotNull(inst);
		assertEquals(addr(0x2002), inst.getMinAddress());
		assertEquals(addr(0x2003), inst.getMaxAddress());
	}

	@Test
	public void testGetInstructionsStartingAt() throws Exception {
		parseStatic(addr(0x1100), addr(0x1200));
		InstructionIterator iter = listing.getInstructions(addr(0x1100), true);
		Address addr = addr(0x1100);
		int cnt = 0;
		while (iter.hasNext()) {
			Instruction inst = iter.next();
			assertNotNull(inst);
			++cnt;
			assertEquals(addr, inst.getMinAddress());
			addr = addr.add(2);
		}

		assertEquals(0x81, cnt);
	}

	@Test
	public void testGetInstructionsForward() throws Exception {
		parseStatic(addr(0x1100), addr(0x1200));
		InstructionIterator iter = listing.getInstructions(addr(0x1000), true);
		Address addr = addr(0x1100);
		int cnt = 0;
		while (iter.hasNext()) {
			Instruction inst = iter.next();
			assertNotNull(inst);
			++cnt;
			assertEquals(addr, inst.getMinAddress());
			addr = addr.add(2);
		}

		assertEquals(0x81, cnt);
	}

	@Test
	public void testGetInstructionsBackwards() throws Exception {
		parseStatic(addr(0x1100), addr(0x1500));
		InstructionIterator iter = listing.getInstructions(addr(0x1600), false);
		Address addr = addr(0x1500);
		int cnt = 0;
		while (iter.hasNext()) {
			Instruction inst = iter.next();
			assertNotNull(inst);
			++cnt;
			assertEquals(addr, inst.getMinAddress());
			addr = addr.subtract(2);
		}

		assertEquals(0x201, cnt);
	}

	@Test
	public void testGetPropertyMap() throws Exception {
		parseStatic(addr(0x1100), addr(0x1500));

		Instruction inst = listing.getInstructionAt(addr(0x1100));
		inst.setProperty("Numbers", 12);

		PropertyMap map = listing.getPropertyMap("Numbers");
		assertNotNull(map);

		inst.setProperty("FavoriteColor", new SaveableColor(Color.RED));

		map = listing.getPropertyMap("FavoriteColor");
		assertNotNull(map);
	}

	@Test
	public void testGetUserDefinedProperties() throws Exception {
		parseStatic(addr(0x1100), addr(0x1500));

		Instruction inst = listing.getInstructionAt(addr(0x1100));
		inst.setProperty("Numbers", 12);
		assertEquals(12, inst.getIntProperty("Numbers"));

		inst.setProperty("FavoriteColor", new SaveableColor(Color.RED));
		SaveableColor c = (SaveableColor) inst.getObjectProperty("FavoriteColor");
		assertNotNull(c);
		assertEquals(Color.RED, c.getColor());

		Iterator<String> iter = listing.getUserDefinedProperties();
		String name1 = iter.next();
		assertNotNull(name1);
		String name2 = iter.next();
		assertNotNull(name2);
		assertTrue(name1.equals("FavoriteColor") || name1.equals("Numbers"));
		assertTrue(name2.equals("FavoriteColor") || name2.equals("Numbers"));
	}

	@Test
	public void testRemoveUserDefinedProperty() throws Exception {
		parseStatic(addr(0x1100), addr(0x1500));
		Instruction inst = listing.getInstructionAt(addr(0x1100));

		inst.setProperty("Numbers", 12);
		listing.removeUserDefinedProperty("Numbers");
		try {
			inst.getIntProperty("Numbers");
			Assert.fail("Should not have gotten property");
		}
		catch (NoValueException e) {
			// expected
		}

		inst.setProperty("FavoriteColor", new SaveableColor(Color.RED));
		SaveableColor c = (SaveableColor) inst.getObjectProperty("FavoriteColor");
		assertNotNull(c);
		listing.removeUserDefinedProperty("FavoriteColor");
		assertNull(inst.getObjectProperty("FavoriteColor"));
	}

	@Test
	public void testRemoveBlock() throws Exception {
		parseStatic(addr(0x1100), addr(0x1500));
		MemoryBlock block = mem.getBlock(addr(0x1000));
		mem.removeBlock(block, new TaskMonitorAdapter());
		assertNull(listing.getInstructionAt(addr(0x1100)));
	}

	@Test
	public void testMoveBlock() throws Exception {
		parseStatic(addr(0x1100), addr(0x1200));
		MemoryBlock block = mem.getBlock(addr(0x1000));
		CodeUnit cu = listing.getCodeUnitContaining(block.getEnd());
		cu.setComment(CodeUnit.EOL_COMMENT, "eol comment");
		Address oldMin = cu.getMinAddress();
		Address expectedNewMin = oldMin.addNoWrap(0x8000 - 0x1000);

		cu.setProperty("Numbers", 12);
		assertEquals(12, cu.getIntProperty("Numbers"));

		cu.setProperty("FavoriteColor", new SaveableColor(Color.RED));
		SaveableColor c = (SaveableColor) cu.getObjectProperty("FavoriteColor");

		mem.moveBlock(block, addr(0x8000), new TaskMonitorAdapter());
		assertNotNull(listing.getInstructionAt(addr(0x8100 + 100)));
		block = mem.getBlock(addr(0x8100 + 100));

		cu = listing.getCodeUnitContaining(block.getEnd());
		assertEquals(expectedNewMin, cu.getMinAddress());
		assertNotNull(cu.getComment(CodeUnit.EOL_COMMENT));

		assertEquals(12, cu.getIntProperty("Numbers"));
		c = (SaveableColor) cu.getObjectProperty("FavoriteColor");
		assertNotNull(c);

	}

	@Test
	public void testCreateData() throws Exception {
		listing.createData(addr(0x1740), DefaultDataType.dataType, 1);
		assertNotNull(listing.getDataAt(addr(0x1740)));

		Structure struct = new StructureDataType("struct_1", 100);
		listing.createData(addr(0x1741), struct, 100);
		Data d = listing.getDataAt(addr(0x1741));
		assertNotNull(d);
		assertTrue(d.getDataType() instanceof Structure);
	}

	@Test
	public void testCompositeDataComments() throws Exception {

		CodeUnit cu = listing.getCodeUnitAt(addr(0x1741));
		cu.setComment(CodeUnit.EOL_COMMENT, "eol comment");
		cu.setComment(CodeUnit.PLATE_COMMENT, "plate comment");
		cu.setComment(CodeUnit.POST_COMMENT, "post comment");
		cu.setComment(CodeUnit.PRE_COMMENT, "pre comment");

		Structure struct = new StructureDataType("struct_1", 0);
		struct.add(DWordDataType.dataType);
		struct.add(DWordDataType.dataType);

		Data structData = listing.createData(addr(0x1741), struct, struct.getLength());
		assertEquals("eol comment", structData.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("plate comment", structData.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("post comment", structData.getComment(CodeUnit.POST_COMMENT));
		assertEquals("pre comment", structData.getComment(CodeUnit.PRE_COMMENT));

		Data firstComp = structData.getComponent(0);
		assertEquals("eol comment", firstComp.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("plate comment", firstComp.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("post comment", firstComp.getComment(CodeUnit.POST_COMMENT));
		assertEquals("pre comment", firstComp.getComment(CodeUnit.PRE_COMMENT));

		structData.setComment(CodeUnit.EOL_COMMENT, "EOL");
		assertEquals("EOL", firstComp.getComment(CodeUnit.EOL_COMMENT));

		firstComp.setComment(CodeUnit.POST_COMMENT, "POST");
		assertEquals("POST", structData.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testCreatePointerDataType() throws Exception {

		Memory memory = program.getMemory();
		memory.setBytes(addr(0x2000), new byte[] { (byte) 0xd7, (byte) 05 });
		Pointer p = new PointerDataType();
		listing.createData(addr(0x2000), p, addr(0x2000).getPointerSize());
		Data data = listing.getDataAt(addr(0x2000));

		assertNotNull(data);
		Object obj = data.getValue();
		assertNotNull(obj);
		assertTrue(obj instanceof Address);
		assertEquals(addr(0xd7050000), obj);
	}

	@Test
	public void testCreateArrayPointersWithSomeNullsDoesntBail() throws Exception {
		Memory memory = program.getMemory();
		memory.setBytes(addr(0x2000), bytes(0, 0, 1, 1));
		Pointer p = new Pointer16DataType();
		assertEquals(2, p.getLength());
		Array pArray = new ArrayDataType(p, 2, 2);
		listing.createData(addr(0x2000), pArray, 4);
		Data data = listing.getDataAt(addr(0x2000));
		assertEquals(2, data.getNumComponents());
		assertEquals(addr(0x0000), data.getComponent(0).getValue());
		assertEquals(addr(0x0101), data.getComponent(1).getValue());
		Reference[] referencesFrom = data.getComponent(0).getReferencesFrom();
		assertEquals(0, referencesFrom.length);
		referencesFrom = data.getComponent(1).getReferencesFrom();
		assertEquals(1, referencesFrom.length);
		assertEquals(addr(0x0101), referencesFrom[0].getToAddress());
	}

	@Test
	public void testGetDataAt() throws Exception {
		listing.createData(addr(0x1740), DefaultDataType.dataType, 1);
		assertNotNull(listing.getDataAt(addr(0x1740)));

		Structure struct = new StructureDataType("struct_1", 0x100);
		listing.createData(addr(0x1741), struct, 0);

		Data d = listing.getDataAt(addr(0x1800));
		assertNull(d);

		d = listing.getDataContaining(addr(0x1800));
		assertNotNull(d);

		assertTrue(d.getDataType() instanceof Structure);

		assertNull(listing.getDefinedDataAt(addr(0x1700)));

		d = listing.getDataContaining(addr(0x1700));
		assertNotNull(d);
		assertFalse(d.isDefined());
	}

	@Test
	public void testGetCodeUnitContaining() throws Exception {
		parseStatic(addr(0x1100), addr(0x1500));

		CodeUnit cu = listing.getCodeUnitContaining(addr(0x1471));
		assertNotNull(cu);
		assertEquals(addr(0x1470), cu.getMinAddress());
	}

	@Test
	public void testGetDataContaining() throws Exception {
		mem.createInitializedBlock("test", addr(0x0), 100, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		StringDataType s = new StringDataType();
		listing.createData(addr(0x0), s, 10);

		Data d = listing.getDefinedDataContaining(addr(0x5));
		assertNotNull(d);
		assertEquals(addr(0x0), d.getMinAddress());
		assertEquals(addr(0x9), d.getMaxAddress());

		d = listing.getDataContaining(addr(0x5));
		assertNotNull(d);
		assertEquals(addr(0x0), d.getMinAddress());
		assertEquals(addr(0x9), d.getMaxAddress());
	}

	@Test
	public void testGetDataAfter() throws Exception {

		Structure struct = new StructureDataType("struct_1", 100);
		listing.createData(addr(0x1741), struct, 100);

		Data d = listing.getDataAfter(addr(0x1745));
		assertNotNull(d);

		d = listing.getDataAfter(addr(0x1740));
		assertTrue(d.getDataType().isEquivalent(struct));
	}

	@Test
	public void testGetDataAfterAtEnd() throws Exception {
		WordDataType dt = new WordDataType();
		Address maxAddr = program.getMaxAddress();
		listing.createData(maxAddr.subtract(1), dt);
		Data d = listing.getDataAt(maxAddr.subtract(1));
		assertNotNull(d);
		d = listing.getDataAfter(maxAddr);
		assertNull(d);
	}

	@Test
	public void testGetDataBefore() throws Exception {
		mem.createInitializedBlock("test", addr(0x0), 200, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		StringDataType s = new StringDataType();
		listing.createData(addr(0x0), s, 10);

		Structure struct = new StructureDataType("struct_1", 100);
		listing.createData(addr(0x50), struct, 100);
		Data d = listing.getDataBefore(addr(0x50));
		assertNotNull(d);
		assertTrue(d.getDataType().isEquivalent(DefaultDataType.dataType));

		d = listing.getDefinedDataBefore(addr(0x49));
		assertNotNull(d);

		assertEquals(addr(0x0), d.getMinAddress());
		assertEquals(addr(0x9), d.getMaxAddress());

	}

	@Test
	public void testGetDataBefore2() throws Exception {
		mem.createInitializedBlock("test", addr(0x0), 200, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		StringDataType s = new StringDataType();
		listing.createData(addr(0x0), s, 0x10);

		parseStatic(addr(0x1100), addr(0x1500));

		// clear 1489 (0x05d1) to 1495 (0x5d7)
		listing.clearCodeUnits(addr(0x1489), addr(0x1495), false);

		listing.createData(addr(0x1489), new StringDataType(), 3);

		Data d = listing.getDefinedDataBefore(addr(0x1492));
		assertNotNull(d);

		assertTrue(d.getDataType() instanceof StringDataType);

		d = listing.getDataBefore(addr(0x10));
		assertEquals(addr(0x0), d.getMinAddress());
		assertEquals(addr(0xf), d.getMaxAddress());

	}

	@Test
	public void testIsUndefined() throws Exception {

		builder.addBytesBranch(0x1000, 0x1010);
		builder.addBytesReturn(0x1002);
		parseStatic(addr(0x1000), addr(0x1003));

		listing.createData(addr(0x1006), WordDataType.dataType);

		mem.createUninitializedBlock("test", addr(0x100), 0x500, false);

		assertTrue(listing.isUndefined(addr(0x200), addr(0x300)));

		parseStatic(addr(0x1100), addr(0x1500));
		assertTrue(!listing.isUndefined(addr(0x300), addr(0x1500)));

		assertTrue(!listing.isUndefined(addr(0x1200), addr(0x1500)));
	}

	@Test
	public void testGetUndefinedRanges() throws Exception {

		parseStatic(addr(0x1100), addr(0x1500));
		listing.createData(addr(0x1080), new StringDataType(), 0x20);

		AddressSet set = new AddressSet(addr(0x0), addr(0x11000));
		AddressSetView undefinedSet = listing.getUndefinedRanges(set, false, null);
		assertNotNull(undefinedSet);
		assertEquals(3, undefinedSet.getNumAddressRanges());

		Iterator<AddressRange> it = undefinedSet.iterator();
		AddressRange range = it.next();
		assertEquals(addr(0x1000), range.getMinAddress());
		assertEquals(addr(0x107f), range.getMaxAddress());

		range = it.next();
		assertEquals(addr(0x10a0), range.getMinAddress());
		assertEquals(addr(0x10ff), range.getMaxAddress());

		range = it.next();
		assertEquals(addr(0x1502), range.getMinAddress());
		assertEquals(addr(0x2fff), range.getMaxAddress());
	}

	@Test
	public void testGetUndefinedDataAt() throws Exception {
		parseStatic(addr(0x1100), addr(0x1500));
		Data d = listing.getUndefinedDataAt(addr(0x1099));
		assertNotNull(d);

		listing.createData(addr(0x1000), new StringDataType(), 0x20);
		d = listing.getUndefinedDataAt(addr(0x1010));
		assertNull(d);

		d = listing.getUndefinedDataAt(addr(0x0fff));
		assertNull(d);

		d = listing.getUndefinedDataAt(addr(0x1021));
		assertNotNull(d);
	}

	@Test
	public void testGetUndefinedDataAfter() throws Exception {
		mem.createInitializedBlock("bk1", addr(0x0), 0x200, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);
		parseStatic(addr(0x1100), addr(0x1500));
		Instruction inst = listing.getInstructionContaining(addr(0x1500));

		Data data = listing.getUndefinedDataAfter(addr(0x100), TaskMonitorAdapter.DUMMY_MONITOR);
		assertNotNull(data);
		assertEquals(addr(0x101), data.getMinAddress());

		data = listing.getUndefinedDataAfter(addr(0x1499), TaskMonitorAdapter.DUMMY_MONITOR);
		assertNotNull(data);
		Address expectedAddr = inst.getMaxAddress().addNoWrap(1);
		assertEquals(expectedAddr, data.getMinAddress());

		data = listing.getUndefinedDataAfter(expectedAddr, TaskMonitorAdapter.DUMMY_MONITOR);
		assertNotNull(data);
		assertEquals(expectedAddr.addNoWrap(1), data.getMinAddress());

		parseStatic(addr(0x1700), addr(0x1705));
		inst = listing.getInstructionContaining(addr(0x1705));
		data = listing.getUndefinedDataAfter(addr(0x16ff), TaskMonitorAdapter.DUMMY_MONITOR);
		expectedAddr = inst.getMaxAddress().next();
		assertEquals(expectedAddr, data.getMinAddress());

		listing.clearCodeUnits(addr(0x1390), addr(0x1400), false);
		data = listing.getUndefinedDataAfter(addr(0x1300), TaskMonitorAdapter.DUMMY_MONITOR);
		assertNotNull(data);
		assertEquals(addr(0x1390), data.getMinAddress());
	}

	@Test
	public void testGetFirstUndefinedData() throws Exception {
		mem.createInitializedBlock("bk1", addr(0x0), 0x200, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);
		parseStatic(addr(0x1100), addr(0x1500));
		Instruction inst = listing.getInstructionContaining(addr(0x1500));

		Data data = listing.getFirstUndefinedData(new AddressSet(addr(0x101), addr(0x500)),
			TaskMonitorAdapter.DUMMY_MONITOR);
		assertNotNull(data);
		assertEquals(addr(0x101), data.getMinAddress());

		data = listing.getFirstUndefinedData(new AddressSet(addr(0x1500), addr(0x2000)),
			TaskMonitorAdapter.DUMMY_MONITOR);
		assertNotNull(data);
		Address expectedAddr = inst.getMaxAddress().addNoWrap(1);
		assertEquals(expectedAddr, data.getMinAddress());

		data = listing.getFirstUndefinedData(
			new AddressSet(expectedAddr.add(1), expectedAddr.add(500)),
			TaskMonitorAdapter.DUMMY_MONITOR);
		assertNotNull(data);
		assertEquals(expectedAddr.addNoWrap(1), data.getMinAddress());

		parseStatic(addr(0x1700), addr(0x1705));
		inst = listing.getInstructionContaining(addr(0x1705));
		data = listing.getFirstUndefinedData(new AddressSet(addr(0x1700), addr(0x5000)),
			TaskMonitorAdapter.DUMMY_MONITOR);
		expectedAddr = inst.getMaxAddress().addNoWrap(1);
		assertEquals(expectedAddr, data.getMinAddress());

		listing.clearCodeUnits(addr(0x1390), addr(0x1400), false);
		data = listing.getFirstUndefinedData(new AddressSet(addr(0x1300), addr(0x5000)),
			TaskMonitorAdapter.DUMMY_MONITOR);
		assertNotNull(data);
		assertEquals(addr(0x1390), data.getMinAddress());
	}

	@Test
	public void testGetUndefinedDataBefore() throws Exception {
		parseStatic(addr(0x1100), addr(0x1500));

		Data data = listing.getUndefinedDataBefore(addr(0x1400), TaskMonitorAdapter.DUMMY_MONITOR);
		assertNotNull(data);
		assertEquals(addr(0x10ff), data.getMinAddress());

		listing.clearCodeUnits(addr(0x1495), addr(0x1500), false);
		data = listing.getUndefinedDataBefore(addr(0x1600), TaskMonitorAdapter.DUMMY_MONITOR);
		assertNotNull(data);
		assertEquals(addr(0x15ff), data.getMinAddress());
	}

	@Test
	public void testClearProperties() throws Exception {
		mem.createInitializedBlock("bk1", addr(0x0), 0x200, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);
		// addresses 10-19
		for (int i = 0; i < 20; i++) {
			CodeUnit cu = listing.getCodeUnitAt(addr(i + 10));
			cu.setProperty("Numbers", i);
			assertTrue(cu.getIntProperty("Numbers") >= 0);
		}

		for (int i = 50; i < 100; i++) {
			CodeUnit cu = listing.getCodeUnitAt(addr(i));
			cu.setProperty("Name", "codeUnit_" + i);
			assertNotNull(cu.getStringProperty("Name"));
		}
		listing.clearProperties(addr(0x0), addr(0x15), TaskMonitorAdapter.DUMMY_MONITOR);
		CodeUnit cu = listing.getCodeUnitAt(addr(0x10));
		try {
			cu.getIntProperty("Numbers");
			Assert.fail("Should not have gotten property!");
		}
		catch (NoValueException e) {
			// expected
		}

		cu = listing.getCodeUnitAt(addr(0x18));
		cu.getIntProperty("Numbers");

		listing.clearProperties(addr(0x16), addr(0x200), TaskMonitorAdapter.DUMMY_MONITOR);
		cu = listing.getCodeUnitAt(addr(0x16));
		try {
			cu.getIntProperty("Numbers");
			Assert.fail("Should not have gotten property!");
		}
		catch (NoValueException e) {
			// expected
		}

		cu = listing.getCodeUnitAt(addr(0x55));
		assertNull(cu.getStringProperty("Name"));
	}

	@Test
	public void testClearAll() throws Exception {

		parseStatic(addr(0x1000), addr(0x1100));
		parseStatic(addr(0x1500), addr(0x1600));

		assertNotNull(listing.getInstructionAt(addr(0x1500)));
		listing.clearAll(false, TaskMonitorAdapter.DUMMY_MONITOR);

		assertNull(listing.getInstructionAt(addr(0x1500)));
		assertEquals(0, listing.getNumInstructions());
	}

	@Test
	public void testGetCommentHistory() throws Exception {

		// TODO: The CodeManager does some strange things to process history
		// records which results in only a single returned CommentHistory for
		// a given timestamp.  It is unclear why this is done and this test
		// does not appear to exercise/verify that functionality.  While
		// reworking this test the timestamp resolution was changed from 1-sec
		// to 1-msec to avoid testing delays.

		CodeUnit cu = listing.getCodeUnitAt(addr(0x1000));
		cu.setComment(CodeUnit.EOL_COMMENT, "This is comment 1");

		Thread.sleep(1);// force a new date to get used
		cu.setComment(CodeUnit.EOL_COMMENT, "This is a changed comment 2");

		Thread.sleep(1);// force a new date to get used
		cu.setComment(CodeUnit.EOL_COMMENT, "This is a changed comment 3");

		CodeManager cm = ((ProgramDB) program).getCodeManager();
		CommentHistory[] history = cm.getCommentHistory(addr(0x1000), CodeUnit.EOL_COMMENT);
		assertEquals(3, history.length);
		assertEquals("This is a changed comment 3", history[0].getComments());
		assertEquals("This is a changed comment 2", history[1].getComments());
		assertEquals("This is comment 1", history[2].getComments());
	}

	@Test
	public void testBasicFlowOverrideRedisassembly() throws Exception {
		builder.addBytesBranch(0x2000, 0x2010);
		builder.addBytesReturn(0x2002);
		parseStatic(addr(0x2000), addr(0x2003));

		ProgramDB pdb = (ProgramDB) program;
		Lock lock = pdb.getLock();

		lock.acquire();
		try {

			Instruction instructionAt = pdb.getListing().getInstructionAt(addr(0x2000));
			assertEquals(FlowOverride.NONE, instructionAt.getFlowOverride());
			instructionAt.setFlowOverride(FlowOverride.CALL);

			instructionAt = pdb.getListing().getInstructionAt(addr(0x2000));
			assertEquals(FlowOverride.CALL, instructionAt.getFlowOverride());

			pdb.getCodeManager().reDisassembleAllInstructions(TaskMonitor.DUMMY);

			instructionAt = pdb.getListing().getInstructionAt(addr(0x2000));
			assertEquals(FlowOverride.CALL, instructionAt.getFlowOverride());
		}
		finally {
			lock.release();
		}
	}

	@Test
	public void testNoFlowRedisassembly() throws Exception {
		builder.addBytesCall(0x2000, 0x2010);
		parseStatic(addr(0x2000), addr(0x2001));

		ProgramDB pdb = (ProgramDB) program;
		Lock lock = pdb.getLock();

		lock.acquire();
		try {

			Instruction instructionAt = pdb.getListing().getInstructionAt(addr(0x2000));
			assertEquals(FlowOverride.NONE, instructionAt.getFlowOverride());

			pdb.getCodeManager().reDisassembleAllInstructions(TaskMonitor.DUMMY);

			instructionAt = pdb.getListing().getInstructionAt(addr(0x2002));
			assertEquals(null, instructionAt);
		}
		finally {
			lock.release();
		}
	}

	private Address addr(long l) {
		return space.getAddress(l);
	}

	private void parseStatic(Address startAddr, Address endAddr) throws Exception {

		Address addr;

		for (addr = startAddr; addr.compareTo(endAddr) <= 0;) {
			parseOne(addr);
			CodeUnit unit = listing.getCodeUnitAt(addr);
			addr = addr.add(unit.getLength());
		}
	}

	private void parseOne(Address atAddr) throws Exception {

		MemBuffer buf = new DumbMemBufferImpl(mem, atAddr);
		ProcessorContext context = new ProgramProcessorContext(program.getProgramContext(), atAddr);
		InstructionPrototype proto = program.getLanguage().parse(buf, context, false);
		listing.createInstruction(atAddr, proto, buf, context);

	}
}
