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

import org.junit.Test;

import ghidra.program.database.OriginalProgramModifierListener;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's symbols in the listing.
 */
public class SymbolMergeManagerNamespace2Test extends AbstractListingMergeManagerTest {

	@Test
	public void testRemoveAndRenameNamespaceChooseLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					symtab.createNameSpace(program.getGlobalNamespace(), "foo",
						SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol namespaceSymbol = symtab.getNamespaceSymbol("foo", null);
					namespaceSymbol.setName("bar", SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol namespaceSymbol = symtab.getNamespaceSymbol("foo", null);
					namespaceSymbol.delete();
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

		});

		resultProgram = mtf.getResultProgram();
		resultAddressFactory = resultProgram.getAddressFactory();

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON_NAME);
		waitForMergeCompletion();

		SymbolTable resultSymbolTable = resultProgram.getSymbolTable();
		Symbol fooSymbol = resultSymbolTable.getNamespaceSymbol("foo", null);
		Symbol barSymbol = resultSymbolTable.getNamespaceSymbol("bar", null);
		Symbol barConflict1Namespace = resultSymbolTable.getNamespaceSymbol("bar_conflict1", null);
		assertNull(fooSymbol);
		assertNotNull(barSymbol);
		assertEquals(SymbolType.NAMESPACE, barSymbol.getSymbolType());
		assertNull(barConflict1Namespace);
	}

	@Test
	public void testRemoveAndRenameNamespaceChooseMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					symtab.createNameSpace(program.getGlobalNamespace(), "foo",
						SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol namespaceSymbol = symtab.getNamespaceSymbol("foo", null);
					namespaceSymbol.setName("bar", SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol namespaceSymbol = symtab.getNamespaceSymbol("foo", null);
					namespaceSymbol.delete();
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

		});

		resultProgram = mtf.getResultProgram();
		resultAddressFactory = resultProgram.getAddressFactory();

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		SymbolTable resultSymbolTable = resultProgram.getSymbolTable();
		Symbol fooSymbol = resultSymbolTable.getNamespaceSymbol("foo", null);
		Symbol barSymbol = resultSymbolTable.getNamespaceSymbol("bar", null);
		Symbol barConflict1Namespace = resultSymbolTable.getNamespaceSymbol("bar_conflict1", null);
		assertNull(fooSymbol);
		assertNull(barSymbol);
		assertNull(barConflict1Namespace);
	}

	@Test
	public void testRenameRemoveNamespaceAndCreateLibChooseLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					symtab.createNameSpace(program.getGlobalNamespace(), "foo",
						SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol namespaceSymbol = symtab.getNamespaceSymbol("foo", null);
					namespaceSymbol.setName("bar", SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol namespaceSymbol = symtab.getNamespaceSymbol("foo", null);
					namespaceSymbol.delete();
					program.getExternalManager().addExternalLibraryName("baz",
						SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

		});

		resultProgram = mtf.getResultProgram();
		resultAddressFactory = resultProgram.getAddressFactory();

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON_NAME);
		waitForMergeCompletion();

		SymbolTable resultSymbolTable = resultProgram.getSymbolTable();
		Symbol fooSymbol = resultSymbolTable.getNamespaceSymbol("foo", null);
		Symbol barSymbol = resultSymbolTable.getNamespaceSymbol("bar", null);
		Symbol bazSymbol = resultSymbolTable.getNamespaceSymbol("baz", null);
		Symbol bazLibrary = resultSymbolTable.getLibrarySymbol("baz");
		Symbol barConflict1Namespace = resultSymbolTable.getNamespaceSymbol("bar_conflict1", null);
		assertNull(fooSymbol);
		assertNotNull(barSymbol);
		assertEquals(SymbolType.NAMESPACE, barSymbol.getSymbolType());
		assertNull(bazSymbol);
		assertNotNull(bazLibrary);
		assertEquals(SymbolType.LIBRARY, bazLibrary.getSymbolType());
		assertNull(barConflict1Namespace);
	}

	@Test
	public void testRenameRemoveNamespaceAndCreateLibChooseMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					symtab.createNameSpace(program.getGlobalNamespace(), "foo",
						SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol namespaceSymbol = symtab.getNamespaceSymbol("foo", null);
					namespaceSymbol.setName("bar", SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol namespaceSymbol = symtab.getNamespaceSymbol("foo", null);
					namespaceSymbol.delete();
					program.getExternalManager().addExternalLibraryName("baz",
						SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

		});

		resultProgram = mtf.getResultProgram();
		resultAddressFactory = resultProgram.getAddressFactory();

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		SymbolTable resultSymbolTable = resultProgram.getSymbolTable();
		Symbol fooSymbol = resultSymbolTable.getNamespaceSymbol("foo", null);
		Symbol barSymbol = resultSymbolTable.getNamespaceSymbol("bar", null);
		Symbol bazSymbol = resultSymbolTable.getNamespaceSymbol("baz", null);
		Symbol bazLibrary = resultSymbolTable.getLibrarySymbol("baz");
		Symbol barConflict1Namespace = resultSymbolTable.getNamespaceSymbol("bar_conflict1", null);
		assertNull(fooSymbol);
		assertNull(barSymbol);
		assertNull(bazSymbol);
		assertNotNull(bazLibrary);
		assertEquals(SymbolType.LIBRARY, bazLibrary.getSymbolType());
		assertNull(barConflict1Namespace);
	}

	@Test
	public void testRemoveAndRenameNamespaceRemoveCheckedOut() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					symtab.createNameSpace(program.getGlobalNamespace(), "foo",
						SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol namespaceSymbol = symtab.getNamespaceSymbol("foo", null);
					namespaceSymbol.setName("bar", SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol namespaceSymbol = symtab.getNamespaceSymbol("foo", null);
					namespaceSymbol.delete();
					program.getExternalManager().addExternalLibraryName("bar",
						SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

		});

		resultProgram = mtf.getResultProgram();
		resultAddressFactory = resultProgram.getAddressFactory();

		executeMerge(ASK_USER);
		chooseRadioButton(REMOVE_CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		SymbolTable resultSymbolTable = resultProgram.getSymbolTable();
		Symbol fooSymbol = resultSymbolTable.getNamespaceSymbol("foo", null);
		Symbol barSymbol = resultSymbolTable.getNamespaceSymbol("bar", null);
		Symbol barConflict1Namespace = resultSymbolTable.getNamespaceSymbol("bar_conflict1", null);
		Symbol barConflict2Namespace = resultSymbolTable.getNamespaceSymbol("bar_conflict2", null);
		Symbol barConflict2Library = resultSymbolTable.getLibrarySymbol("bar_conflict2");
		assertNull(fooSymbol);
		assertNotNull(barSymbol);
		assertEquals(SymbolType.NAMESPACE, barSymbol.getSymbolType());
		assertNull(barConflict1Namespace);
		assertNull(barConflict2Namespace);
		assertNull(barConflict2Library);
	}

	@Test
	public void testRemoveAndRenameNamespaceRenameCheckedOut() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					symtab.createNameSpace(program.getGlobalNamespace(), "foo",
						SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol namespaceSymbol = symtab.getNamespaceSymbol("foo", null);
					namespaceSymbol.setName("bar", SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol namespaceSymbol = symtab.getNamespaceSymbol("foo", null);
					namespaceSymbol.delete();
					program.getExternalManager().addExternalLibraryName("bar",
						SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

		});

		resultProgram = mtf.getResultProgram();
		resultAddressFactory = resultProgram.getAddressFactory();

		executeMerge(ASK_USER);
		chooseRadioButton(RENAME_CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		SymbolTable resultSymbolTable = resultProgram.getSymbolTable();
		Symbol fooSymbol = resultSymbolTable.getNamespaceSymbol("foo", null);
		Symbol barSymbol = resultSymbolTable.getNamespaceSymbol("bar", null);
		Symbol barConflict1Namespace = resultSymbolTable.getNamespaceSymbol("bar_conflict1", null);
		Symbol barConflict2Namespace = resultSymbolTable.getNamespaceSymbol("bar_conflict2", null);
		Symbol barConflict1Library = resultSymbolTable.getLibrarySymbol("bar_conflict1");
		Symbol barConflict2Library = resultSymbolTable.getLibrarySymbol("bar_conflict2");
		assertNull(fooSymbol);
		assertNotNull(barSymbol);
		assertEquals(SymbolType.NAMESPACE, barSymbol.getSymbolType());
		assertNull(barConflict1Namespace);
		assertNull(barConflict2Namespace);
		assertNotNull(barConflict1Library);
		assertEquals(SymbolType.LIBRARY, barConflict1Library.getSymbolType());
		assertNull(barConflict2Library);
	}

	@Test
	public void testRenameNamespaceVsAddLibrary() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					symtab.createNameSpace(program.getGlobalNamespace(), "foo",
						SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol namespaceSymbol = symtab.getNamespaceSymbol("foo", null);
					namespaceSymbol.setName("bar", SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				try {
					program.getExternalManager().addExternalLibraryName("bar",
						SourceType.USER_DEFINED);
				}
				finally {
					program.endTransaction(txId, true);
				}
			}

		});

		resultProgram = mtf.getResultProgram();
		resultAddressFactory = resultProgram.getAddressFactory();

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		SymbolTable resultSymbolTable = resultProgram.getSymbolTable();
		Symbol fooSymbol = resultSymbolTable.getNamespaceSymbol("foo", null);
		Symbol barSymbol = resultSymbolTable.getNamespaceSymbol("bar", null);
		Symbol barConflict1Namespace = resultSymbolTable.getNamespaceSymbol("bar_conflict1", null);
		Symbol barConflict2Namespace = resultSymbolTable.getNamespaceSymbol("bar_conflict2", null);
		Symbol barConflict1Library = resultSymbolTable.getLibrarySymbol("bar_conflict1");
		Symbol barConflict2Library = resultSymbolTable.getLibrarySymbol("bar_conflict2");
		assertNull(fooSymbol);
		assertNotNull(barSymbol);
		assertEquals(SymbolType.NAMESPACE, barSymbol.getSymbolType());
		assertNull(barConflict1Namespace);
		assertNull(barConflict2Namespace);
		assertNotNull(barConflict1Library);
		assertEquals(SymbolType.LIBRARY, barConflict1Library.getSymbolType());
		assertNull(barConflict2Library);
	}
}
