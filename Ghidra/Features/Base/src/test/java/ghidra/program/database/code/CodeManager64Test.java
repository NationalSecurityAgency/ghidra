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

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;

/**
 * Test the code manager portion of listing.
 *
 *
 */
public class CodeManager64Test extends AbstractGenericTest {

	private Listing listing;
	private AddressSpace space;
	private Program program;
	private Memory mem;
	private int transactionID;

	/**
	 * Constructor for CodeManagerTest.
	 * @param arg0
	 */
	public CodeManager64Test() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY64_LE, this);
		builder.createMemory("B1", "1000", 0x2000);

		program = builder.getProgram();

		space = program.getAddressFactory().getDefaultAddressSpace();
		listing = program.getListing();
		mem = program.getMemory();
		transactionID = program.startTransaction("Test");

		for (int i = 0; i < 40; i++) {
			mem.setInt(addr(0x2000 + i), i);
		}
	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	@Test
	public void testCreateArrayPointers64() throws Exception {
		Memory memory = program.getMemory();
		memory.setBytes(addr(0x2000),
			bytes(1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0));
		Pointer p = new Pointer64DataType();
		assertEquals(8, p.getLength());
		Array pArray = new ArrayDataType(p, 3, 24);
		listing.createData(addr(0x2000), pArray, 24);
		Data data = listing.getDataAt(addr(0x2000));

		assertEquals(3, data.getNumComponents());
		assertEquals(addr(0x0000000100000001L), data.getComponent(0).getValue());
		assertEquals(addr(0x0000000100000002L), data.getComponent(1).getValue());
		assertEquals(addr(0x0000000100000003L), data.getComponent(2).getValue());

		Reference[] referencesFrom = data.getComponent(0).getReferencesFrom();
		assertEquals(1, referencesFrom.length);
		assertEquals(addr(0x0000000100000001L), referencesFrom[0].getToAddress());

		referencesFrom = data.getComponent(1).getReferencesFrom();
		assertEquals(1, referencesFrom.length);
		assertEquals(addr(0x0000000100000002L), referencesFrom[0].getToAddress());

		// limit of 2 new 32 bit segments can be created from array of pointers
		referencesFrom = data.getComponent(2).getReferencesFrom();
		assertEquals(1, referencesFrom.length);
		assertEquals(addr(0x0000000100000003L), referencesFrom[0].getToAddress());

	}

	@Test
	public void testCreateArrayPointers64WithMoreThanAllowed32Segments() throws Exception {
		Memory memory = program.getMemory();
		memory.setBytes(addr(0x2000),
			bytes(1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0));
		Pointer p = new Pointer64DataType();
		assertEquals(8, p.getLength());
		Array pArray = new ArrayDataType(p, 3, 24);
		listing.createData(addr(0x2000), pArray, 24);
		Data data = listing.getDataAt(addr(0x2000));
		assertEquals(3, data.getNumComponents());
		assertEquals(addr(0x0000000100000001L), data.getComponent(0).getValue());
		assertEquals(addr(0x0000000200000002L), data.getComponent(1).getValue());
		assertEquals(addr(0x0000000300000003L), data.getComponent(2).getValue());

		Reference[] referencesFrom = data.getComponent(0).getReferencesFrom();
		assertEquals(1, referencesFrom.length);
		assertEquals(addr(0x0000000100000001L), referencesFrom[0].getToAddress());

		referencesFrom = data.getComponent(1).getReferencesFrom();
		assertEquals(1, referencesFrom.length);
		assertEquals(addr(0x0000000200000002L), referencesFrom[0].getToAddress());

		// limit of 2 new 32 bit segments can be created from array of pointers
		referencesFrom = data.getComponent(2).getReferencesFrom();
		assertEquals(0, referencesFrom.length);

	}

	private Address addr(long l) {
		return space.getAddress(l);
	}

//	private void addBlocks() throws Exception {
//		File ramblockoneFile = findTestDataFile("ramblockone");
//		File ramblocktwoFile = findTestDataFile("ramblocktwo");
//		File ramblockthreeFile = findTestDataFile("ramblockthree");
//
//		FileInputStream fis1 = new FileInputStream(ramblockoneFile);
//		FileInputStream fis2 = new FileInputStream(ramblocktwoFile);
//		FileInputStream fis3 = new FileInputStream(ramblockthreeFile);
//
//		byte[] bytesOne = new byte[(int) ramblockoneFile.length()];
//		byte[] bytesTwo = new byte[(int) ramblocktwoFile.length()];
//		byte[] bytesThree = new byte[(int) ramblockthreeFile.length()];
//
//		DataInputStream dis = new DataInputStream(fis1);
//		boolean done = false;
//		int i = 0;
//
//		while (!done) {
//			try {
//				bytesOne[i] = dis.readByte();
//				i++;
//			}
//			catch (EOFException e) {
//				done = true;
//			}
//		}
//		fis1.close();
//
//		done = false;
//		dis = new DataInputStream(fis2);
//		i = 0;
//
//		while (!done) {
//			try {
//				bytesTwo[i] = dis.readByte();
//				i++;
//			}
//			catch (EOFException e) {
//				done = true;
//			}
//		}
//		fis2.close();
//
//		done = false;
//		dis = new DataInputStream(fis3);
//		i = 0;
//
//		while (!done) {
//			try {
//				bytesThree[i] = dis.readByte();
//				i++;
//			}
//			catch (EOFException e) {
//				done = true;
//			}
//		}
//		fis3.close();
//		TaskMonitor m = TaskMonitorAdapter.DUMMY_MONITOR;
//		mem.createInitializedBlock("B1", addr(1000), new ByteArrayInputStream(bytesOne),
//			bytesOne.length, m, false);
//		mem.createInitializedBlock("B2", addr(10000), new ByteArrayInputStream(bytesTwo),
//			bytesTwo.length, m, false);
//		mem.createInitializedBlock("B3", addr(0x21000), new ByteArrayInputStream(bytesThree),
//			bytesThree.length, m, false);
//	}

}
