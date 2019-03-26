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
package ghidra.program.database.external;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class ExternalManagerDBTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private AddressSpace space;
	private ExternalManagerDB extMgr;
	private int transactionID;

	public ExternalManagerDBTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, this);
		space = program.getAddressFactory().getDefaultAddressSpace();
		extMgr = (ExternalManagerDB) program.getExternalManager();
		transactionID = program.startTransaction("Test");
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.endTransaction(transactionID, true);
			program.release(this);
		}
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

	@Test
	public void testAddExtLocation()
			throws IOException, InvalidInputException, DuplicateNameException {

		ExternalLocation loc1 =
			extMgr.addExtLocation("ext1", "label0", null, SourceType.USER_DEFINED);
		assertEquals("ext1", loc1.getLibraryName());
		assertEquals("label0", loc1.getLabel());

		ExternalLocation loc2 =
			extMgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED);
		assertEquals("ext1", loc2.getLibraryName());
		assertEquals("label1", loc2.getLabel());

		ExternalLocation loc3 =
			extMgr.addExtLocation("ext2", "label1", null, SourceType.USER_DEFINED);
		assertEquals("ext2", loc3.getLibraryName());
		assertEquals("label1", loc3.getLabel());

		ExternalLocation loc4 =
			extMgr.addExtLocation("ext2", "label2", null, SourceType.USER_DEFINED);

		ExternalLocation loc5 =
			extMgr.addExtLocation("ext2", null, addr(2000), SourceType.USER_DEFINED);

		try {
			extMgr.addExtLocation("ext2", null, null, SourceType.USER_DEFINED);
			Assert.fail();
		}
		catch (InvalidInputException e) {
			// expected
		}

		extMgr.addExtLocation("ext1", "label1", addr(1500), SourceType.USER_DEFINED);

		extMgr.invalidateCache(true);

		String[] names = extMgr.getExternalLibraryNames();
		assertEquals(2, names.length);
		assertEquals("ext1", names[0]);
		assertEquals("ext2", names[1]);

		assertEquals(loc1, extMgr.getExtLocation(loc1.getExternalSpaceAddress()));
		assertEquals(loc2, extMgr.getExtLocation(loc2.getExternalSpaceAddress()));
		assertEquals(loc3, extMgr.getExtLocation(loc3.getExternalSpaceAddress()));
		assertEquals(loc4, extMgr.getExtLocation(loc4.getExternalSpaceAddress()));
		assertEquals(loc5, extMgr.getExtLocation(loc5.getExternalSpaceAddress()));

	}

	@Test
	public void testGetExternalLocationsByLibraryName()
			throws InvalidInputException, DuplicateNameException {

		extMgr.addExtLocation("ext1", "label0", null, SourceType.USER_DEFINED);
		extMgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED);
		ExternalLocation loc3 =
			extMgr.addExtLocation("ext2", "label1", null, SourceType.USER_DEFINED);
		ExternalLocation loc4 =
			extMgr.addExtLocation("ext2", "label2", null, SourceType.USER_DEFINED);

		ExternalLocation loc5 =
			extMgr.addExtLocation("ext2", null, addr(2000), SourceType.USER_DEFINED);

		ExternalLocationIterator iter = extMgr.getExternalLocations("ext2");
		assertTrue(iter.hasNext());
		assertEquals(loc3, iter.next());
		assertTrue(iter.hasNext());
		assertEquals(loc4, iter.next());
		assertTrue(iter.hasNext());
		assertEquals(loc5, iter.next());
		assertTrue(!iter.hasNext());
		assertNull(iter.next());

	}

	@Test
	public void testGetExternalLocationsByMemAddr()
			throws InvalidInputException, DuplicateNameException {

		extMgr.addExtLocation("ext1", "label0", null, SourceType.USER_DEFINED);
		extMgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED);
		extMgr.addExtLocation("ext2", "label1", null, SourceType.USER_DEFINED);
		extMgr.addExtLocation("ext2", "label2", null, SourceType.USER_DEFINED);

		ExternalLocation loc5 =
			extMgr.addExtLocation("ext2", null, addr(2000), SourceType.USER_DEFINED);

		ExternalLocationIterator iter = extMgr.getExternalLocations(addr(2000));
		assertTrue(iter.hasNext());
		assertEquals(loc5, iter.next());
		assertTrue(!iter.hasNext());
		assertNull(iter.next());

	}

	@Test
	public void testGetExternalLocationByName()
			throws InvalidInputException, DuplicateNameException {

//		ExternalLocation loc1 =
//			extMgr.addExtLocation("ext1", "label0", null, SourceType.USER_DEFINED);
//		ExternalLocation loc2 =
//			extMgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED);
//		ExternalLocation loc3 =
//			extMgr.addExtLocation("ext2", "label1", null, SourceType.USER_DEFINED);
//		ExternalLocation loc4 =
//			extMgr.addExtLocation("ext2", "label2", null, SourceType.USER_DEFINED);

		ExternalLocation loc5 =
			extMgr.addExtLocation("ext2", null, addr(2000), SourceType.USER_DEFINED);

//		assertEquals(loc1, extMgr.getExternalLocation("ext1", "label0"));
//		assertEquals(loc2, extMgr.getExternalLocation("ext1", "label1"));
//		assertEquals(loc3, extMgr.getExternalLocation("ext2", "label1"));
//		assertEquals(loc4, extMgr.getExternalLocation("ext2", "label2"));
		assertEquals(loc5, extMgr.getUniqueExternalLocation("ext2", loc5.getLabel()));

	}

	@Test
	public void testGetExternalLocationByName2()
			throws InvalidInputException, DuplicateNameException {

		ExternalLocation loc1 =
			extMgr.addExtLocation("ext1", "label0", null, SourceType.USER_DEFINED);
		ExternalLocation loc2 =
			extMgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED);
		ExternalLocation loc3 =
			extMgr.addExtLocation("ext2", "label1", null, SourceType.USER_DEFINED);
		ExternalLocation loc4 =
			extMgr.addExtLocation("ext2", "label2", null, SourceType.USER_DEFINED);

		ExternalLocation loc5 =
			extMgr.addExtLocation("ext2", null, addr(2000), SourceType.USER_DEFINED);

		Symbol s = getUniqueSymbol(program, "ext1");
		assertTrue("ext1 library not found", s != null && s.getSymbolType() == SymbolType.LIBRARY);
		Library ext1 = (Library) s.getObject();
		s = getUniqueSymbol(program, "ext2");
		assertTrue("ext2 library not found", s != null && s.getSymbolType() == SymbolType.LIBRARY);
		Library ext2 = (Library) s.getObject();

		assertEquals(loc2, extMgr.getUniqueExternalLocation(ext1, "label1"));
		assertEquals(loc3, extMgr.getUniqueExternalLocation(ext2, "label1"));
		assertEquals(loc4, extMgr.getUniqueExternalLocation(ext2, "label2"));
		assertEquals(loc5, extMgr.getUniqueExternalLocation(ext2, loc5.getLabel()));

	}

	@Test
	public void testRemoveExternalLocation() throws InvalidInputException, DuplicateNameException {

		extMgr.addExtLocation("ext1", "label0", null, SourceType.USER_DEFINED);
		extMgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED);
		ExternalLocation loc3 =
			extMgr.addExtLocation("ext2", "label1", null, SourceType.USER_DEFINED);
		ExternalLocation loc4 =
			extMgr.addExtLocation("ext2", "label2", null, SourceType.USER_DEFINED);

		ExternalLocation loc5 =
			extMgr.addExtLocation("ext2", null, addr(2000), SourceType.USER_DEFINED);

		extMgr.removeExternalLocation(loc4.getExternalSpaceAddress());

		ExternalLocationIterator iter = extMgr.getExternalLocations("ext2");
		assertTrue(iter.hasNext());
		assertEquals(loc3, iter.next());
		assertTrue(iter.hasNext());
		assertEquals(loc5, iter.next());
		assertTrue(!iter.hasNext());
		assertNull(iter.next());

	}

	@Test
	public void testUpdateExternalProgramName()
			throws DuplicateNameException, InvalidInputException {

		ExternalLocation loc1 =
			extMgr.addExtLocation("ext1", "label0", null, SourceType.USER_DEFINED);
		ExternalLocation loc2 =
			extMgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED);
		ExternalLocation loc3 =
			extMgr.addExtLocation("ext2", "label1", null, SourceType.USER_DEFINED);
		ExternalLocation loc4 =
			extMgr.addExtLocation("ext2", "label2", null, SourceType.USER_DEFINED);

		ExternalLocation loc5 =
			extMgr.addExtLocation("ext2", null, addr(2000), SourceType.USER_DEFINED);

		try {
			extMgr.updateExternalLibraryName("ext2", "ext1", SourceType.USER_DEFINED);
			Assert.fail();
		}
		catch (DuplicateNameException e) {
			// expected
		}

		extMgr.updateExternalLibraryName("ext2", "ext3", SourceType.USER_DEFINED);

		String[] names = extMgr.getExternalLibraryNames();
		assertEquals(2, names.length);
		assertEquals("ext1", names[0]);
		assertEquals("ext3", names[1]);

		assertEquals(loc1, extMgr.getExtLocation(loc1.getExternalSpaceAddress()));
		assertEquals(loc2, extMgr.getExtLocation(loc2.getExternalSpaceAddress()));
		assertEquals(loc3, extMgr.getExtLocation(loc3.getExternalSpaceAddress()));
		assertEquals(loc4, extMgr.getExtLocation(loc4.getExternalSpaceAddress()));
		assertEquals(loc5, extMgr.getExtLocation(loc5.getExternalSpaceAddress()));
		assertEquals("ext3", loc5.getLibraryName());

		ExternalLocationIterator iter = extMgr.getExternalLocations("ext3");
		assertTrue(iter.hasNext());
		assertEquals(loc3, iter.next());
		assertTrue(iter.hasNext());
		assertEquals(loc4, iter.next());
		assertTrue(iter.hasNext());
		assertEquals(loc5, iter.next());
		assertTrue(!iter.hasNext());
		assertNull(iter.next());

		assertTrue(!extMgr.getExternalLocations("ext2").hasNext());

	}

	@Test
	public void testGetSetExternalPath() throws InvalidInputException, DuplicateNameException {

		extMgr.addExtLocation("ext1", "label0", null, SourceType.USER_DEFINED);
		extMgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED);
		extMgr.addExtLocation("ext2", "label1", null, SourceType.USER_DEFINED);
		extMgr.addExtLocation("ext2", "label2", null, SourceType.USER_DEFINED);

		extMgr.addExtLocation("ext2", null, addr(2000), SourceType.USER_DEFINED);

		assertNull(extMgr.getExternalLibraryPath("ext2"));
		extMgr.setExternalPath("ext2", "/a/b/c", true);
		assertEquals("/a/b/c", extMgr.getExternalLibraryPath("ext2"));

		assertNull(extMgr.getExternalLibraryPath("ext1"));
	}

	@Test
	public void testSetRelativeExternalPath() throws InvalidInputException, DuplicateNameException {
		extMgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED);

		try {
			extMgr.setExternalPath("ext2", "relative/path/value", true);
			Assert.fail("Incorrectly allowed to enter set a relative external path");
		}
		catch (InvalidInputException iie) {
			// good!
		}
	}

	@Test
	public void testClearExternalPathWithNullValue()
			throws InvalidInputException, DuplicateNameException {

		extMgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED);
		assertNull(extMgr.getExternalLibraryPath("ext1"));

		extMgr.setExternalPath("ext1", "/a/b/c", true);
		assertEquals("External path not set", "/a/b/c", extMgr.getExternalLibraryPath("ext1"));

		extMgr.setExternalPath("ext1", null, true);
		assertNull("External path was not cleared", extMgr.getExternalLibraryPath("ext1"));
	}

	@Test
	public void testOriginalImportName()
			throws InvalidInputException, DuplicateNameException, CircularDependencyException {
		ExternalLocation extLoc =
			extMgr.addExtLocation("ext1", "foo", addr(1000), SourceType.IMPORTED);

		extLoc.setName(extLoc.getParentNameSpace(), "bar", SourceType.ANALYSIS);

		assertEquals("bar", extLoc.getLabel());
		assertEquals("foo", extLoc.getOriginalImportedName());
		assertEquals(SourceType.ANALYSIS, extLoc.getSource());

		extLoc.restoreOriginalName();

		assertEquals("foo", extLoc.getLabel());
		assertEquals(null, extLoc.getOriginalImportedName());
		assertEquals(SourceType.IMPORTED, extLoc.getSource());

	}
}
