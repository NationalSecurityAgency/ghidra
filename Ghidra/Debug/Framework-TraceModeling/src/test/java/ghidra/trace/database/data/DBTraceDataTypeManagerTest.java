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
package ghidra.trace.database.data;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.*;

import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.DBTrace;
import ghidra.util.InvalidNameException;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.ConsoleTaskMonitor;

public class DBTraceDataTypeManagerTest extends AbstractGhidraHeadlessIntegrationTest {
	protected Language toyLanguage;
	protected DBTrace trace;
	protected DBTraceDataTypeManager dtm;

	@Before
	public void setUp() throws IOException {
		toyLanguage = DefaultLanguageService.getLanguageService()
				.getLanguage(
					new LanguageID("Toy:BE:64:default"));
		trace = new DBTrace("Testing", toyLanguage.getDefaultCompilerSpec(), this);
		dtm = trace.getDataTypeManager();
	}

	@After
	public void tearDown() {
		trace.release(this);
	}

	protected StructureDataType getTestDataType() {
		StructureDataType mine =
			new StructureDataType(new CategoryPath("/Some/Path"), "TestType", 0);
		mine.add(UnsignedLongLongDataType.dataType, "f0", null);
		mine.add(UnsignedLongDataType.dataType, "f8", null);
		mine.add(UnsignedLongDataType.dataType, "fc", null);
		return mine;
	}

	protected StructureDataType getTestDataTypeB() {
		StructureDataType mine =
			new StructureDataType(new CategoryPath("/Some/Path"), "TestTypeB", 0);
		mine.add(UnsignedLongDataType.dataType, "f0", null);
		mine.add(UnsignedLongLongDataType.dataType, "f4", null);
		mine.add(UnsignedLongDataType.dataType, "fc", null);
		return mine;
	}

	@Test
	public void testGetName() {
		assertEquals("Testing", dtm.getName());
	}

	@Test
	public void testSetName() throws InvalidNameException {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			dtm.setName("Another name");
		}
		assertEquals("Another name", trace.getName());
	}

	@Test
	public void testAddSourceArchive() throws IOException {
		StructureDataType mine = getTestDataType();
		DataTypePath minePath = mine.getDataTypePath();
		Path tmpDir = Files.createTempDirectory("test");
		File archiveFile = tmpDir.resolve("test.gdt").toFile();
		FileDataTypeManager dtm2 = FileDataTypeManager.createFileArchive(archiveFile);
		try (UndoableTransaction tid = UndoableTransaction.start(dtm2, "Testing", true)) {
			dtm2.addDataType(mine, DataTypeConflictHandler.DEFAULT_HANDLER);
		}
		DataType got = dtm2.getDataType(minePath);

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			dtm.addDataType(got, DataTypeConflictHandler.DEFAULT_HANDLER);
		}
		dtm2.delete();

		// TODO: Listen for sourceArchiveAdded event

		assertEquals(1, dtm.getSourceArchives().size());
	}

	@Test
	public void testAddAndGet() {
		StructureDataType mine = getTestDataType();
		DataTypePath minePath = mine.getDataTypePath();
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			dtm.addDataType(mine, DataTypeConflictHandler.REPLACE_HANDLER);
		}

		DataType got = dtm.getDataType(minePath);
		assertEquals(mine.toString(), got.toString()); // TODO: Eww
	}

	@Test
	@Ignore("TODO")
	public void testAddRemoveUndoThenGet() throws IOException {
		StructureDataType mine = getTestDataType();
		DataTypePath minePath = mine.getDataTypePath();
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			dtm.addDataType(mine, DataTypeConflictHandler.REPLACE_HANDLER);
		}

		DataType got = dtm.getDataType(minePath);
		assertEquals(mine.toString(), got.toString()); // TODO: Eww

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "To Undo", true)) {
			dtm.remove(got, new ConsoleTaskMonitor());
		}

		assertNull(got = dtm.getDataType(minePath));

		trace.undo();

		got = dtm.getDataType(minePath);
		assertEquals(mine.toString(), got.toString()); // TODO: Eww
	}

	@Test
	public void testChangeDataType() {
		StructureDataType mine = getTestDataType();
		DataTypePath minePath = mine.getDataTypePath();
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			dtm.addDataType(mine, DataTypeConflictHandler.REPLACE_HANDLER);

			Structure got = (Structure) dtm.getDataType(minePath);
			got.replace(1, LongDataType.dataType, 4, "sf4", "changed to signed");
		}
		// TODO: Install listeners and verify event notifications
		// TODO: Test that changes to data types are reflected in the listing(s)
	}

	@Test
	@Ignore("TODO")
	public void testReplaceDataType() throws DataTypeDependencyException {
		StructureDataType mineA = getTestDataType();
		DataTypePath mineAPath = mineA.getDataTypePath();
		StructureDataType mineB = getTestDataTypeB();
		DataTypePath mineBPath = mineB.getDataTypePath();
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			dtm.addDataType(mineA, DataTypeConflictHandler.REPLACE_HANDLER);

			DataType got = dtm.getDataType(mineAPath);
			dtm.replaceDataType(got, mineB, true);
		}

		assertNull(dtm.getDataType(mineAPath));
		assertEquals(mineB.toString(), dtm.getDataType(mineBPath).toString());
	}

	@Test
	public void testMoveDataType() throws DuplicateNameException {
		StructureDataType mine = getTestDataType();
		DataTypePath minePath = mine.getDataTypePath();
		DataType got;
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			dtm.addDataType(mine, DataTypeConflictHandler.REPLACE_HANDLER);

			got = dtm.getDataType(minePath);
			got.setCategoryPath(new CategoryPath("/Another/Path"));
		}

		assertNull(dtm.getDataType(minePath));
		assertEquals(got, dtm.getDataType(new DataTypePath("/Another/Path", "TestType")));
	}

	@Test
	public void testRenameDataType() throws InvalidNameException, DuplicateNameException {
		StructureDataType mine = getTestDataType();
		DataTypePath minePath = mine.getDataTypePath();
		DataType got;
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			dtm.addDataType(mine, DataTypeConflictHandler.REPLACE_HANDLER);

			got = dtm.getDataType(minePath);
			got.setName("RenamedType");
		}

		assertNull(dtm.getDataType(minePath));
		assertEquals(got, dtm.getDataType(new DataTypePath("/Some/Path", "RenamedType")));
	}

	@Test
	public void testCreateCategory() {
		Category category;
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			category = dtm.createCategory(new CategoryPath("/Another/Path"));
		}
		assertEquals(category, dtm.getCategory(new CategoryPath("/Another/Path")));
	}

	@Test
	public void testMoveCategory() throws DuplicateNameException {
		Category toMove;
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			Category category = dtm.createCategory(new CategoryPath("/Another/Path"));
			toMove = dtm.createCategory(new CategoryPath("/MoveMe"));
			category.moveCategory(toMove, new ConsoleTaskMonitor());
		}
		assertEquals(toMove, dtm.getCategory(new CategoryPath("/Another/Path/MoveMe")));
	}

	@Test
	public void testRenameCategory() throws DuplicateNameException, InvalidNameException {
		Category category;
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			category = dtm.createCategory(new CategoryPath("/Another/Path"));
			category.setName("Renamed");
		}
		assertEquals(category, dtm.getCategory(new CategoryPath("/Another/Renamed")));
	}

	@Test
	public void testRemoveCategory() {
		Category category;
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			category = dtm.createCategory(new CategoryPath("/Another/Path"));
		}
		assertEquals(category, dtm.getCategory(new CategoryPath("/Another/Path")));

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Testing", true)) {
			dtm.getCategory(new CategoryPath("/Another"))
					.removeEmptyCategory("Path",
						new ConsoleTaskMonitor());
		}
		assertNull(dtm.getCategory(new CategoryPath("/Another/Path")));
	}
}
