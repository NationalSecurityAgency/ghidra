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
package ghidra.app.merge.listing;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.database.external.ExternalManagerDB;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;

/**
 * Test the merge of the versioned program's listing.
 */
public class ExternalProgramMergerTest extends AbstractListingMergeManagerTest {

	/**
	 *
	 * @param arg0
	 */
	public ExternalProgramMergerTest() {
		super();
	}

	@Test
	public void testChangePathNoConflicts() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					program.getExternalManager().setExternalPath("COMDLG32.DLL", "//comdlg32.dll",
						true);
					program.getExternalManager().setExternalPath("KERNEL32.DLL", "//kernel32.dll",
						true);
					commit = true;
				}
				catch (InvalidInputException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					program.getExternalManager().setExternalPath("GDI32.DLL", "//gdi32.dll", true);
					program.getExternalManager().setExternalPath("KERNEL32.DLL", "//kernel32.dll",
						true);
					commit = true;
				}
				catch (InvalidInputException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager resultExtMgr = resultProgram.getExternalManager();
		String[] names = resultExtMgr.getExternalLibraryNames();
		assertEquals(8, names.length);
		Arrays.sort(names);
		String[] expectedNames = new String[] { "ADVAPI32.DLL", "COMDLG32.DLL", "GDI32.DLL",
			"KERNEL32.DLL", "MSVCRT.DLL", "SHELL32.DLL", "USER32.DLL", "WINSPOOL.DRV" };
		assertTrue(Arrays.equals(expectedNames, names));
		assertEquals("//advapi32.dll", resultExtMgr.getExternalLibraryPath("ADVAPI32.DLL"));
		assertEquals("//comdlg32.dll", resultExtMgr.getExternalLibraryPath("COMDLG32.DLL"));
		assertEquals("//gdi32.dll", resultExtMgr.getExternalLibraryPath("GDI32.DLL"));
		assertEquals("//kernel32.dll", resultExtMgr.getExternalLibraryPath("KERNEL32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("MSVCRT.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("SHELL32.DLL"));
		assertEquals("//user32.dll", resultExtMgr.getExternalLibraryPath("USER32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("WINSPOOL.DRV"));
	}

	@Test
	public void testPathConflicts() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					program.getExternalManager().setExternalPath("ADVAPI32.DLL", "//foo.dll", true);
					program.getExternalManager().setExternalPath("KERNEL32.DLL", "//latest.dll",
						true);
					commit = true;
				}
				catch (InvalidInputException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					program.getExternalManager().setExternalPath("ADVAPI32.DLL", "//bar.dll", true);
					program.getExternalManager().setExternalPath("KERNEL32.DLL", "//my.dll", true);
					commit = true;
				}
				catch (InvalidInputException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Program Name Conflict", LATEST_BUTTON_NAME);
		chooseButtonAndApply("Resolve External Program Name Conflict", CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		ExternalManager resultExtMgr = resultProgram.getExternalManager();
		String[] names = resultExtMgr.getExternalLibraryNames();
		assertEquals(8, names.length);
		Arrays.sort(names);
		String[] expectedNames = new String[] { "ADVAPI32.DLL", "COMDLG32.DLL", "GDI32.DLL",
			"KERNEL32.DLL", "MSVCRT.DLL", "SHELL32.DLL", "USER32.DLL", "WINSPOOL.DRV" };
		assertTrue(Arrays.equals(expectedNames, names));
		assertEquals("//foo.dll", resultExtMgr.getExternalLibraryPath("ADVAPI32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("COMDLG32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("GDI32.DLL"));
		assertEquals("//my.dll", resultExtMgr.getExternalLibraryPath("KERNEL32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("MSVCRT.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("SHELL32.DLL"));
		assertEquals("//user32.dll", resultExtMgr.getExternalLibraryPath("USER32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("WINSPOOL.DRV"));
	}

	@Test
	public void testRemoveWithoutConflicts() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					removeExternalLibrary(program, "ADVAPI32.DLL");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					removeExternalLibrary(program, "USER32.DLL");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager resultExtMgr = resultProgram.getExternalManager();
		String[] names = resultExtMgr.getExternalLibraryNames();
		assertEquals(6, names.length);
		Arrays.sort(names);
		String[] expectedNames = new String[] { "COMDLG32.DLL", "GDI32.DLL", "KERNEL32.DLL",
			"MSVCRT.DLL", "SHELL32.DLL", "WINSPOOL.DRV" };
		assertTrue(Arrays.equals(expectedNames, names));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("COMDLG32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("GDI32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("KERNEL32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("MSVCRT.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("SHELL32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("WINSPOOL.DRV"));
	}

	@Test
	public void testRemoveConflictsKeepLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					removeExternalLibrary(program, "ADVAPI32.DLL");
					program.getExternalManager().setExternalPath("USER32.DLL", "//latest.dll",
						true);
					commit = true;
				}
				catch (InvalidInputException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					program.getExternalManager().setExternalPath("ADVAPI32.DLL", "//my.dll", true);
					removeExternalLibrary(program, "USER32.DLL");
					commit = true;
				}
				catch (InvalidInputException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Program Name Conflict", LATEST_BUTTON_NAME);
		chooseButtonAndApply("Resolve External Program Name Conflict", LATEST_BUTTON_NAME);
		waitForMergeCompletion();

		ExternalManager resultExtMgr = resultProgram.getExternalManager();

		// Check a couple external symbols to see they were removed with the refs.
		ExternalLocation extLoc =
			resultExtMgr.getUniqueExternalLocation("ADVAPI32.DLL", "IsTextUnicode");
		assertNull(extLoc);
		extLoc = resultExtMgr.getUniqueExternalLocation("ADVAPI32.DLL", "RegQueryValueExW");
		assertNull(extLoc);

		String[] names = resultExtMgr.getExternalLibraryNames();
		assertEquals(7, names.length);
		Arrays.sort(names);
		String[] expectedNames = new String[] { "COMDLG32.DLL", "GDI32.DLL", "KERNEL32.DLL",
			"MSVCRT.DLL", "SHELL32.DLL", "USER32.DLL", "WINSPOOL.DRV" };
		assertTrue(Arrays.equals(expectedNames, names));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("COMDLG32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("GDI32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("KERNEL32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("MSVCRT.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("SHELL32.DLL"));
		assertEquals("//latest.dll", resultExtMgr.getExternalLibraryPath("USER32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("WINSPOOL.DRV"));
	}

	@Test
	public void testRemoveConflictsKeepMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					removeExternalLibrary(program, "ADVAPI32.DLL");
					program.getExternalManager().setExternalPath("USER32.DLL", "//latest.dll",
						true);
					commit = true;
				}
				catch (InvalidInputException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					program.getExternalManager().setExternalPath("ADVAPI32.DLL", "//my.dll", true);
					removeExternalLibrary(program, "USER32.DLL");
					commit = true;
				}
				catch (InvalidInputException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Program Name Conflict", CHECKED_OUT_BUTTON_NAME);
		chooseButtonAndApply("Resolve External Program Name Conflict", CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		ExternalManager resultExtMgr = resultProgram.getExternalManager();

		// Check a couple external symbols to see they were removed with the refs.
		ExternalLocation extLoc =
			resultExtMgr.getUniqueExternalLocation("ADVAPI32.DLL", "IsTextUnicode");
		assertNull(extLoc);
		extLoc = resultExtMgr.getUniqueExternalLocation("ADVAPI32.DLL", "RegQueryValueExW");
		assertNull(extLoc);

		String[] names = resultExtMgr.getExternalLibraryNames();
		assertEquals(7, names.length);
		Arrays.sort(names);
		String[] expectedNames = new String[] { "ADVAPI32.DLL", "COMDLG32.DLL", "GDI32.DLL",
			"KERNEL32.DLL", "MSVCRT.DLL", "SHELL32.DLL", "WINSPOOL.DRV" };
		assertTrue(Arrays.equals(expectedNames, names));
		assertEquals("//my.dll", resultExtMgr.getExternalLibraryPath("ADVAPI32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("COMDLG32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("GDI32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("KERNEL32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("MSVCRT.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("SHELL32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("WINSPOOL.DRV"));
	}

	@Test
	public void testRemoveRefsConflictKeepMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					removeExternalLibrary(program, "ADVAPI32.DLL");
					program.getExternalManager().setExternalPath("USER32.DLL", "//latest.dll",
						true);
					commit = true;
				}
				catch (InvalidInputException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					program.getExternalManager().setExternalPath("ADVAPI32.DLL", "//my.dll", true);
					removeExternalLibrary(program, "USER32.DLL");
					commit = true;
				}
				catch (InvalidInputException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Program Name Conflict", CHECKED_OUT_BUTTON_NAME);
		chooseButtonAndApply("Resolve External Program Name Conflict", CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		// Check a couple external symbols to see they were removed with the refs.
		ExternalManager resultExtMgr = resultProgram.getExternalManager();
		ExternalLocation extLoc =
			resultExtMgr.getUniqueExternalLocation("ADVAPI32.DLL", "IsTextUnicode");
		assertNull(extLoc);
		extLoc = resultExtMgr.getUniqueExternalLocation("ADVAPI32.DLL", "RegQueryValueExW");
		assertNull(extLoc);

		String[] names = resultExtMgr.getExternalLibraryNames();
		assertEquals(7, names.length);
		Arrays.sort(names);
		String[] expectedNames = new String[] { "ADVAPI32.DLL", "COMDLG32.DLL", "GDI32.DLL",
			"KERNEL32.DLL", "MSVCRT.DLL", "SHELL32.DLL", "WINSPOOL.DRV" };
		assertTrue(Arrays.equals(expectedNames, names));
		assertEquals("//my.dll", resultExtMgr.getExternalLibraryPath("ADVAPI32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("COMDLG32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("GDI32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("KERNEL32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("MSVCRT.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("SHELL32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("WINSPOOL.DRV"));
	}

	@Test
	public void testRemoveRefKeepSymbol() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				ReferenceManager rm = program.getReferenceManager();
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					rm.removeAllReferencesFrom(addr(program, "0x1001000")); // remove ref to IsTextUnicode
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				ReferenceManager rm = program.getReferenceManager();
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					rm.removeAllReferencesFrom(addr(program, "0x1001008")); // remove ref to RegQueryValueExW
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ReferenceManager rm = resultProgram.getReferenceManager();
		ExternalManager resultExtMgr = resultProgram.getExternalManager();

		Reference[] refs = rm.getReferencesFrom(addr("0x1001000"));
		assertEquals(0, refs.length);
		ExternalLocation extLoc =
			resultExtMgr.getUniqueExternalLocation("ADVAPI32.DLL", "IsTextUnicode");
		assertNotNull(extLoc);

		refs = rm.getReferencesFrom(addr("0x1001008"));
		assertEquals(0, refs.length);
		extLoc = resultExtMgr.getUniqueExternalLocation("ADVAPI32.DLL", "RegQueryValueExW");
		assertNotNull(extLoc);

		String[] names = resultExtMgr.getExternalLibraryNames();
		assertEquals(8, names.length);
		Arrays.sort(names);
		String[] expectedNames = new String[] { "ADVAPI32.DLL", "COMDLG32.DLL", "GDI32.DLL",
			"KERNEL32.DLL", "MSVCRT.DLL", "SHELL32.DLL", "USER32.DLL", "WINSPOOL.DRV" };
		assertTrue(Arrays.equals(expectedNames, names));
		assertEquals("//advapi32.dll", resultExtMgr.getExternalLibraryPath("ADVAPI32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("COMDLG32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("GDI32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("KERNEL32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("MSVCRT.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("SHELL32.DLL"));
		assertEquals("//user32.dll", resultExtMgr.getExternalLibraryPath("USER32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("WINSPOOL.DRV"));
	}

	@Test
	public void testRemoveLibRenameExtSymConflictRemoveBoth() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					removeExternalLibrary(program, "ADVAPI32.DLL");
					String[] names = program.getExternalManager().getExternalLibraryNames();
					Reference[] refs =
						program.getReferenceManager().getReferencesFrom(addr(program, "0x10011e4")); // SetCursor
					SymbolTable symTab = program.getSymbolTable();
					Symbol s = symTab.getSymbol(refs[0]);
					s.setName("SetCursor99", SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Reference[] refs =
						program.getReferenceManager().getReferencesFrom(addr(program, "0x1001004")); // RegCreateKeyW
					SymbolTable symTab = program.getSymbolTable();
					Symbol s = symTab.getSymbol(refs[0]);
					s.setName("RegCreateKeyW99", SourceType.USER_DEFINED);
					removeExternalLibrary(program, "USER32.DLL");
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Remove Conflict", LATEST_BUTTON_NAME);
		chooseButtonAndApply("Resolve External Remove Conflict", CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		ExternalManager resultExtMgr = resultProgram.getExternalManager();

		// Check a couple external symbols to see they were removed with the refs.
		ExternalLocation extLoc =
			resultExtMgr.getUniqueExternalLocation("ADVAPI32.DLL", "IsTextUnicode");
		assertNull(extLoc);
		extLoc = resultExtMgr.getUniqueExternalLocation("ADVAPI32.DLL", "RegQueryValueExW");
		assertNull(extLoc);

		String[] names = resultExtMgr.getExternalLibraryNames();
		assertEquals(6, names.length);
		Arrays.sort(names);
		String[] expectedNames = new String[] { "COMDLG32.DLL", "GDI32.DLL", "KERNEL32.DLL",
			"MSVCRT.DLL", "SHELL32.DLL", "WINSPOOL.DRV" };
		assertTrue(Arrays.equals(expectedNames, names));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("COMDLG32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("GDI32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("KERNEL32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("MSVCRT.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("SHELL32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("WINSPOOL.DRV"));
	}

	@Test
	public void testRemoveLibRenameExtSymConflictKeepBoth() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					removeExternalLibrary(program, "ADVAPI32.DLL");
					Reference[] refs =
						program.getReferenceManager().getReferencesFrom(addr(program, "0x10011e4")); // SetCursor
					SymbolTable symTab = program.getSymbolTable();
					Symbol s = symTab.getSymbol(refs[0]);
					s.setName("SetCursor99", SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Reference[] refs =
						program.getReferenceManager().getReferencesFrom(addr(program, "0x1001004")); // RegCreateKeyW
					SymbolTable symTab = program.getSymbolTable();
					Symbol s = symTab.getSymbol(refs[0]);
					s.setName("RegCreateKeyW99", SourceType.USER_DEFINED);
					removeExternalLibrary(program, "USER32.DLL");
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Remove Conflict", CHECKED_OUT_BUTTON_NAME);
		chooseButtonAndApply("Resolve External Remove Conflict", LATEST_BUTTON_NAME);
		waitForReadTextDialog("External Program Name Merge Information", "Didn't remove", 5000);
		waitForMergeCompletion();

		ExternalManager resultExtMgr = resultProgram.getExternalManager();
		String[] names = resultExtMgr.getExternalLibraryNames();
		assertEquals(8, names.length);
		Arrays.sort(names);
		String[] expectedNames = new String[] { "ADVAPI32.DLL", "COMDLG32.DLL", "GDI32.DLL",
			"KERNEL32.DLL", "MSVCRT.DLL", "SHELL32.DLL", "USER32.DLL", "WINSPOOL.DRV" };
		assertTrue(Arrays.equals(expectedNames, names));
		assertEquals("//advapi32.dll", resultExtMgr.getExternalLibraryPath("ADVAPI32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("COMDLG32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("GDI32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("KERNEL32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("MSVCRT.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("SHELL32.DLL"));
		assertEquals("//user32.dll", resultExtMgr.getExternalLibraryPath("USER32.DLL"));
		assertEquals(null, resultExtMgr.getExternalLibraryPath("WINSPOOL.DRV"));

		// Check that the 2 renames happened.
		ExternalLocation extLoc =
			resultExtMgr.getUniqueExternalLocation("ADVAPI32.DLL", "RegCreateKeyW");
		assertNull(extLoc);
		extLoc = resultExtMgr.getUniqueExternalLocation("ADVAPI32.DLL", "RegCreateKeyW99");
		assertNotNull(extLoc);
		extLoc = resultExtMgr.getUniqueExternalLocation("USER32.DLL", "SetCursor");
		assertNull(extLoc);
		extLoc = resultExtMgr.getUniqueExternalLocation("USER32.DLL", "SetCursor99");
		assertNotNull(extLoc);

	}

//	private void chooseComponent(final String componentName) throws Exception {
//		waitForPrompting(true, 4000);
//		final JPanel comp = getConflictsPanel();
//		assertNotNull(comp);
//		Window window = SwingUtilities.getWindowAncestor(comp);
//		assertNotNull(window);
//		try {
//			pressButtonByName(comp, componentName, false);
////			if (componentName.equals(LATEST_BUTTON)) {
////				sleep(1000);
////				pressButtonByName(comp, MY_BUTTON, false);
////				sleep(1000);
////				pressButtonByName(comp, LATEST_BUTTON, false);
////			}
//			waitForApply(window, true, 2000);
//			pressButtonByText(window, "Apply");
//			waitForPostedSwingRunnables();
//			waitForPrompting(false, 2000);
//
//		}
//		catch (UsrException e) {
//			Assert.fail(e.getMessage());
//		}
//	}
//
//	/**
//	 * @param i
//	 */
//	private void waitForApply(Window window, boolean enabled, int applyMS) throws Exception {
//
//		JButton applyButton = findButtonByText(window, "Apply");
//		assertNotNull(applyButton);
//		int totalTime = 0;
//		while (totalTime <= applyMS) {
//			if (applyButton.isEnabled() == enabled) {
//				return;
//			}
//			try {
//				Thread.sleep(100);
//				totalTime += 100;
//			}
//			catch (InterruptedException e) {
//				Assert.fail("Failed waiting for Apply to be " + (enabled ? "enabled." : "disabled.") +
//					e.getMessage());
//			}
//		}
//		Assert.fail("Failed waiting for Apply to be " + (enabled ? "enabled." : "disabled."));
//	}
//
//	protected JPanel getConflictsPanel() throws Exception {
//		int count = 0;
//		ConflictPanel panel = null;
//		while (panel == null && count < 100) {
//			panel = findComponent(mergeTool.getToolFrame(), ConflictPanel.class, true);
//			Thread.sleep(50);
//			++count;
//		}
//		assertNotNull(panel);
//		return panel;
//	}

	private void removeExternalLibrary(Program program, String libName) {
		ExternalManager extMgr = program.getExternalManager();
		ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
		while (iter.hasNext()) {
			ExternalLocation loc = iter.next();
			if (!((ExternalManagerDB) extMgr).removeExternalLocation(
				loc.getExternalSpaceAddress())) {
				Assert.fail("Couldn't remove external location for library " + libName);
			}
		}
		if (!extMgr.removeExternalLibrary(libName)) {
			Assert.fail("Couldn't remove external library " + libName);
		}
	}
}
