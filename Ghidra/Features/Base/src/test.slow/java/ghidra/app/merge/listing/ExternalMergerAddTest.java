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

import java.util.List;

import org.junit.Test;

import ghidra.app.merge.ProgramMultiUserMergeManager;
import ghidra.program.database.MergeProgram;
import ghidra.program.database.MergeProgramModifier;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class ExternalMergerAddTest extends AbstractExternalMergerTest {

	// *** NotepadMergeListingTest ***

	// External Refs
	// 01001000: op0 to ADVAPI32.DLL IsTextUnicode 77dc4f85
	// 01001004: op0 to ADVAPI32.DLL RegCreateKeyW 77db90b0
	// 01001008: op0 to ADVAPI32.DLL RegQueryValueExW 77db8078
	// 0100100c: op0 to ADVAPI32.DLL RegSetValueExW 77db9348
	// 01001010: op0 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
	// 01001014: op0 to ADVAPI32.DLL RegQueryValueExA 77db858e
	// 01001018: op0 to ADVAPI32.DLL RegCloseKey 77db7d4d
	// 010010c0: op0 to KERNEL32.DLL LocalFree 77e9499c
	// 010010c4: op0 to KERNEL32.DLL GetProcAddress 77e9564b
	// 010013cc: no ref (has string)
	// 010013d8: no ref (has string)
	// 010013f0: no ref (has string)

	// Mem Refs
	// 01001a92: op0 to 01001370 DAT_01001370 DATA primary user
	// 01001abb: op0 to 01001ac1 LAB_01001ac1 CONDITIONAL_JUMP primary
	// 01001aec: op1 to 01001398 AddrTable010080c0Element36 DATA primary
	// 01001b5f: op0 to 010061e3 FUN_010061e3 UNCONDITIONAL_CALL primary

	// Stack Refs
	// 01001a55: op1 no ref to stack offset 0x10
	// 01001af5: op0 to stack offset -0x24a
	// 01001b03: op1 to stack offset -0x24c
	// 01002125: op0 to stack offset -0x10
	// 010024ea: op1 no ref to stack offset 0x10
	// 01002510: op0 no ref to stack offset 0x8
	// 01002a05: op0 no ref to stack offset -0x18

	protected static final Reference ExternalReference = null;

	public ExternalMergerAddTest() {
		super();
	}

	@Override
	protected ProgramMultiUserMergeManager createMergeManager(ProgramChangeSet resultChangeSet,
			ProgramChangeSet myChangeSet) {

		// NOTE: this makes the tests faster.  If you need visual debugging, then make this true
		boolean showListingPanels = false;

		ProgramMultiUserMergeManager mergeManger =
			new ProgramMultiUserMergeManager(resultProgram, myProgram, originalProgram,
				latestProgram, resultChangeSet, myChangeSet, showListingPanels);

		return mergeManger;
	}

	@Test
	public void testAddSameExtLibraryNoConflict() throws Exception {

		final String libname = "advapi32.dll";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {
			@Override
			public void modifyLatest(MergeProgram program) throws Exception {
				program.addExternalLibraryName(libname, SourceType.IMPORTED);
			}

			@Override
			public void modifyPrivate(MergeProgram program) throws Exception {
				program.addExternalLibraryName(libname, SourceType.IMPORTED);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertEquals(true, externalManager.contains(libname));
	}

	@Test
	public void testAddSameExtLibraryDiffSourceConflict() throws Exception {

		final String libname = "advapi32.dll";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {
			@Override
			public void modifyLatest(MergeProgram program) throws Exception {
				program.addExternalLibraryName(libname, SourceType.IMPORTED);
			}

			@Override
			public void modifyPrivate(MergeProgram program) throws Exception {
				program.addExternalLibraryName(libname, SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		// No conflict since external function merger only merges source type when merging name change.
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertEquals(true, externalManager.contains(libname));
	}

	@Test
	public void testAddSameExtLabelNoAddressNoConflict() throws Exception {

		final String libname = "advapi32.dll";
		final String label = "printf";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {
			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, null, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertNull(externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, null, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertNull(externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label, externalLocation.toString());
		assertNull(externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(false, externalLocation.isFunction());
	}

	@Test
	public void testAddSameExtLabelSameAddressNoConflict() throws Exception {

		final String libname = "advapi32.dll";
		final String label = "printf";
		final String address = "77db1020";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {
			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label, externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(false, externalLocation.isFunction());
	}

	@Test
	public void testAddSameExtLabelWithDiffAddressConflictKeepLatest() throws Exception {

		final String libname = "advapi32.dll";
		final String label = "printf";
		final String address1 = "0x100";
		final String address2 = "0x110";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, address1, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address1), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, address2, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address2), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label, externalLocation.toString());
		assertEquals(addr(resultProgram, address1), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(false, externalLocation.isFunction());

		ExternalLocation externalLocation2 =
			externalManager.getUniqueExternalLocation(libname, label + "_conflict1");
		assertNull(externalLocation2);
	}

	@Test
	public void testAddSameExtLabelWithDiffAddressConflictKeepMy() throws Exception {

		final String libname = "advapi32.dll";
		final String label = "printf";
		final String address1 = "0x100";
		final String address2 = "0x110";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, address1, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address1), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, address2, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address2), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));

		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);
		assertEquals(libname + "::" + label, externalLocation.toString());
		assertEquals(addr(resultProgram, address2), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(false, externalLocation.isFunction());

		ExternalLocation externalLocation2 =
			externalManager.getUniqueExternalLocation(libname, label + "_conflict1");
		assertNull(externalLocation2);
	}

	@Test
	public void testAddSameExtLabelWithDiffAddressConflictKeepBoth() throws Exception {

		final String libname = "advapi32.dll";
		final String label = "printf";
		final String address1 = "0x100";
		final String address2 = "0x110";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, address1, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address1), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, address2, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address2), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", KEEP_BOTH_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		List<ExternalLocation> externals = externalManager.getExternalLocations(libname, label);
		assertEquals(2, externals.size());
		ExternalLocationIterator loc1It = externalManager.getExternalLocations(addr(address1));
		assertTrue(loc1It.hasNext());
		assertEquals(label, loc1It.next().getLabel());
		assertTrue(!loc1It.hasNext());

		ExternalLocationIterator loc2It = externalManager.getExternalLocations(addr(address2));
		assertTrue(loc2It.hasNext());
		assertEquals(label, loc2It.next().getLabel());
		assertTrue(!loc2It.hasNext());

	}

	@Test
	public void testAddLabelVsNamespaceAutoMerge() throws Exception {

		final String libname = "user32.dll";
		final String label = "blue";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(library, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);

				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.createNamespace(library, label, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));

				Symbol namespaceSymbol = getUniqueSymbol(program, label, library);
				assertNotNull(namespaceSymbol);
				assertEquals(SymbolType.NAMESPACE, namespaceSymbol.getSymbolType());

				assertTrue(namespaceSymbol.getSource() == SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label, externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(false, externalLocation.isFunction());

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		SymbolTable symtab = resultProgram.getSymbolTable();

		assertNotNull(symtab.getNamespace(label, externalLibrary));

		assertEquals(libname, externalLocation.getLibraryName());
		assertEquals(label, externalLocation.getLabel());
	}

	@Test
	public void testAddNamespaceVsLabelAutoMerge() throws Exception {

		final String libname = "user32.dll";
		final String label = "blue";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {

				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.createNamespace(library, label, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				assertNotNull(program.getSymbolTable().getNamespace(label, library));
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(library, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);

				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);

			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label, externalLocation.toString());
		assertNotNull(externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(false, externalLocation.isFunction());

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		SymbolTable symtab = resultProgram.getSymbolTable();

		Namespace blue = symtab.getNamespace(label, externalLibrary);
		assertTrue(blue.isExternal());
	}

	@Test
	public void testAddFunctionVsLabelAutoMerge() throws Exception {

		final String libname = "user32.dll";
		final String label = "blue";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.addExternalFunction(library, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);

				assertNotNull(externalLocation);
				assertEquals(true, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(library, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);

				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);

			}
		});

		executeMerge(ASK_USER);
//		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label, externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(true, externalLocation.isFunction());

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		Symbol blue = getUniqueSymbol(resultProgram, label, externalLibrary);
		Symbol blueConflict = getUniqueSymbol(resultProgram, label + "_conflict1", externalLibrary);
		assertNotNull(blue);
		assertNull(blueConflict);
		assertEquals(SymbolType.FUNCTION, blue.getSymbolType());
		assertTrue(blue.isExternal());
		ExternalLocation externalLocation1 = externalManager.getExternalLocation(blue);
		assertNotNull(externalLocation1);
		assertEquals(libname, externalLocation1.getLibraryName());
		assertEquals(label, externalLocation1.getLabel());
	}

	@Test
	public void testAddLabelVsFunctionAutoMerge() throws Exception {

		final String libname = "user32.dll";
		final String label = "blue";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.addExternalFunction(library, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);

				assertNotNull(externalLocation);
				assertEquals(true, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(library, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);

				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);

			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label, externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(true, externalLocation.isFunction());

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		Symbol blue = getUniqueSymbol(resultProgram, label, externalLibrary);
		Symbol blueConflict = getUniqueSymbol(resultProgram, label + "_conflict1", externalLibrary);
		assertNotNull(blue);
		assertNull(blueConflict);
		assertEquals(SymbolType.FUNCTION, blue.getSymbolType());
		assertTrue(blue.isExternal());
		ExternalLocation externalLocation1 = externalManager.getExternalLocation(blue);
		assertNotNull(externalLocation1);
		assertEquals(libname, externalLocation1.getLibraryName());
		assertEquals(label, externalLocation1.getLabel());
	}

	@Test
	public void testAddFunctionVsDataLabelConflictKeepLatest() throws Exception {

		final String libname = "user32.dll";
		final String label = "blue";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.addExternalFunction(library, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);

				assertNotNull(externalLocation);
				assertEquals(true, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(library, label, address, new WordDataType(),
					SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);

				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);

			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Function Versus Data Type Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label, externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(true, externalLocation.isFunction());

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		Symbol blue = getUniqueSymbol(resultProgram, label, externalLibrary);
		Symbol blueConflict = getUniqueSymbol(resultProgram, label + "_conflict1", externalLibrary);
		assertNotNull(blue);
		assertNull(blueConflict);
		assertEquals(SymbolType.FUNCTION, blue.getSymbolType());
		assertTrue(blue.isExternal());
		ExternalLocation externalLocation1 = externalManager.getExternalLocation(blue);
		assertEquals(libname, externalLocation1.getLibraryName());
		assertEquals(label, externalLocation1.getLabel());
	}

	@Test
	public void testAddFunctionVsDataLabelConflictKeepMy() throws Exception {

		final String libname = "user32.dll";
		final String label = "blue";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.addExternalFunction(library, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);

				assertNotNull(externalLocation);
				assertEquals(true, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(library, label, address, new WordDataType(),
					SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);

				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);

			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Function Versus Data Type Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label, externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(false, externalLocation.isFunction());

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		Symbol blue = getUniqueSymbol(resultProgram, label, externalLibrary);
		Symbol blueConflict = getUniqueSymbol(resultProgram, label + "_conflict1", externalLibrary);
		assertNotNull(blue);
		assertNull(blueConflict);
		assertEquals(SymbolType.LABEL, blue.getSymbolType());
		assertTrue(blue.isExternal());
		ExternalLocation externalLocation1 = externalManager.getExternalLocation(blue);
		assertEquals(libname, externalLocation1.getLibraryName());
		assertEquals(label, externalLocation1.getLabel());
	}

	@Test
	public void testAddDataLabelVsFunctionConflictKeepLatest() throws Exception {

		final String libname = "user32.dll";
		final String label = "blue";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(library, label, address, new WordDataType(),
					SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);

				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.addExternalFunction(library, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);

				assertNotNull(externalLocation);
				assertEquals(true, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Function Versus Data Type Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		Symbol blue = getUniqueSymbol(resultProgram, label, externalLibrary);
		Symbol blueConflict = getUniqueSymbol(resultProgram, label + "_conflict1", externalLibrary);
		assertNotNull(blue);
		assertNull(blueConflict);
		assertEquals(SymbolType.LABEL, blue.getSymbolType());
		assertTrue(blue.isExternal());
		ExternalLocation externalLocation = externalManager.getExternalLocation(blue);
		assertNotNull(externalLocation);
		assertEquals(libname, externalLocation.getLibraryName());
		assertEquals(label, externalLocation.getLabel());
		assertEquals(libname + "::" + label, externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(false, externalLocation.isFunction());
	}

	@Test
	public void testAddDataLabelVsFunctionConflictKeepMy() throws Exception {

		final String libname = "user32.dll";
		final String label = "blue";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(library, label, address, new WordDataType(),
					SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);

				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.addExternalFunction(library, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);

				assertNotNull(externalLocation);
				assertEquals(true, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Function Versus Data Type Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		Symbol blue = getUniqueSymbol(resultProgram, label, externalLibrary);
		Symbol blueConflict = getUniqueSymbol(resultProgram, label + "_conflict1", externalLibrary);
		assertNotNull(blue);
		assertNull(blueConflict);
		assertEquals(SymbolType.FUNCTION, blue.getSymbolType());
		assertTrue(blue.isExternal());
		ExternalLocation externalLocation = externalManager.getExternalLocation(blue);
		assertNotNull(externalLocation);
		assertEquals(libname, externalLocation.getLibraryName());
		assertEquals(label, externalLocation.getLabel());
		assertEquals(libname + "::" + label, externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(true, externalLocation.isFunction());
	}

	@Test
	public void testAddDiffExtLabelWithSameAddressKeepLatest() throws Exception {

		final String libname = "advapi32.dll";
		final String label1 = "apples";
		final String label2 = "oranges";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label1, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label1);
				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label1, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label2, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label2);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label2, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label1);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label1, externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(false, externalLocation.isFunction());

		externalLocation = externalManager.getUniqueExternalLocation(libname, label2);
		assertNull(externalLocation);
	}

	@Test
	public void testAddDiffExtLabelWithSameAddressKeepMy() throws Exception {

		final String libname = "advapi32.dll";
		final String label1 = "apples";
		final String label2 = "oranges";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label1, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label1);
				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label1, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label2, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label2);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label2, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", MY_BUTTON);// Choose "oranges" labeled external.
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label1);
		assertNull(externalLocation);

		externalLocation = externalManager.getUniqueExternalLocation(libname, label2);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label2, externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(false, externalLocation.isFunction());
	}

	/**
	 * The external function merger only detects and merges source differences when a name
	 * difference is being merged.
	 */
	@Test
	public void testAddSameExtLabelWithDiffSourceNoConflict() throws Exception {

		final String libname = "advapi32.dll";
		final String label = "printf";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, address, SourceType.IMPORTED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.IMPORTED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label, externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.IMPORTED);
		assertEquals(false, externalLocation.isFunction());
	}

	@Test
	public void testAddExtNoLabelSameAddressNoConflict() throws Exception {

		final String libname = "advapi32.dll";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, null, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				String defaultExternalName =
					SymbolUtilities.getDefaultExternalName(addr(program, address), null);
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, defaultExternalName);
				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::EXT_00000100", externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.DEFAULT);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, null, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				String defaultExternalName =
					SymbolUtilities.getDefaultExternalName(addr(program, address), null);
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, defaultExternalName);
				assertNotNull(externalLocation);

				assertEquals(libname + "::EXT_00000100", externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.DEFAULT);
				assertEquals(false, externalLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		String defaultExternalName =
			SymbolUtilities.getDefaultExternalName(addr(resultProgram, address), null);
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, defaultExternalName);
		assertNotNull(externalLocation);

		assertEquals(libname + "::EXT_00000100", externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.DEFAULT);
		assertEquals(false, externalLocation.isFunction());
	}

	@Test
	public void testAddExtFunctionNoLabelSameAddressNoConflict() throws Exception {

		final String libname = "advapi32.dll";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalFunction(libname, null, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				String defaultExternalName =
					SymbolUtilities.getDefaultExternalFunctionName(addr(program, address));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, defaultExternalName);
				assertNotNull(externalLocation);
				assertEquals(true, externalLocation.isFunction());

				assertEquals(libname + "::EXT_FUN_00000100", externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.DEFAULT);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalFunction(libname, null, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				String defaultExternalName =
					SymbolUtilities.getDefaultExternalFunctionName(addr(program, address));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, defaultExternalName);
				assertNotNull(externalLocation);

				assertEquals(libname + "::EXT_FUN_00000100", externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.DEFAULT);
				assertEquals(true, externalLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		String defaultExternalName =
			SymbolUtilities.getDefaultExternalFunctionName(addr(resultProgram, address));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, defaultExternalName);
		assertNotNull(externalLocation);

		assertEquals(libname + "::EXT_FUN_00000100", externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.DEFAULT);
		assertEquals(true, externalLocation.isFunction());
	}

	@Test
	public void testAddExtFunctionNoLabelLatestOnlyNoConflict() throws Exception {

		final String libname = "advapi32.dll";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalFunction(libname, null, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				String defaultExternalName =
					SymbolUtilities.getDefaultExternalFunctionName(addr(program, address));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, defaultExternalName);
				assertNotNull(externalLocation);
				assertEquals(true, externalLocation.isFunction());

				assertEquals(libname + "::EXT_FUN_00000100", externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.DEFAULT);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalFunction(libname, null, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				String defaultExternalName =
					SymbolUtilities.getDefaultExternalFunctionName(addr(program, address));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, defaultExternalName);
				assertNotNull(externalLocation);

				assertEquals(libname + "::EXT_FUN_00000100", externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.DEFAULT);
				assertEquals(true, externalLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		String defaultExternalName =
			SymbolUtilities.getDefaultExternalFunctionName(addr(resultProgram, address));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, defaultExternalName);
		assertNotNull(externalLocation);

		assertEquals(libname + "::EXT_FUN_00000100", externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.DEFAULT);
		assertEquals(true, externalLocation.isFunction());
	}

	@Test
	public void testAddExtFunctionNoLabelMyOnlyNoConflict() throws Exception {

		final String libname = "advapi32.dll";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalFunction(libname, null, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				String defaultExternalName =
					SymbolUtilities.getDefaultExternalFunctionName(addr(program, address));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, defaultExternalName);
				assertNotNull(externalLocation);

				assertEquals(libname + "::EXT_FUN_00000100", externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.DEFAULT);
				assertEquals(true, externalLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		String defaultExternalName =
			SymbolUtilities.getDefaultExternalFunctionName(addr(resultProgram, address));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, defaultExternalName);
		assertNotNull(externalLocation);

		assertEquals(libname + "::EXT_FUN_00000100", externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.DEFAULT);
		assertEquals(true, externalLocation.isFunction());
	}

	@Test
	public void testAddExtFunctionSameLabelSameAddressNoConflict() throws Exception {

		final String libname = "advapi32.dll";
		final String label = "apples";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalFunction(libname, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);
				assertEquals(true, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalFunction(libname, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(true, externalLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label, externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(true, externalLocation.isFunction());
	}

	@Test
	public void testAddExtLabelVsExtFunctionNoAddressNoConflict() throws Exception {

		final String libname = "advapi32.dll";
		final String label = "printf";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, null, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertNull(externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalFunction(libname, label, null, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertNull(externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(true, externalLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label, externalLocation.toString());
		assertNull(externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(true, externalLocation.isFunction());
	}

	@Test
	public void testAddExtFunctionVsExtLabelNoAddressNoConflict() throws Exception {

		final String libname = "advapi32.dll";
		final String label = "printf";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalFunction(libname, label, null, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertNull(externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(true, externalLocation.isFunction());
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, null, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertNull(externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label, externalLocation.toString());
		assertNull(externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(true, externalLocation.isFunction());
	}

	@Test
	public void testAddExtFunctionWithAddressVsNoAddressNoConflict() throws Exception {

		final String libname = "advapi32.dll";
		final String label = "printf";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalFunction(libname, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);
				assertEquals(true, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalFunction(libname, label, null, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertNull(externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(true, externalLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label, externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(true, externalLocation.isFunction());
	}

	@Test
	public void testAddExtFunctionNoAddressVsWithAddressNoConflict() throws Exception {

		final String libname = "advapi32.dll";
		final String label = "printf";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalFunction(libname, label, null, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertNull(externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(true, externalLocation.isFunction());
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalFunction(libname, label, address, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);
				assertEquals(true, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(libname, label);
		assertNotNull(externalLocation);

		assertEquals(libname + "::" + label, externalLocation.toString());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(true, externalLocation.isFunction());
	}

	@Test
	public void testAddSameExternalLibraryNoConflict() throws Exception {

		final String libname = "user32.dll";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Symbol externalLibrarySymbol = resultProgram.getSymbolTable().getLibrarySymbol(libname);
		assertNotNull(externalLibrarySymbol);
		assertEquals(SymbolType.LIBRARY, externalLibrarySymbol.getSymbolType());

		Symbol conflictSymbol =
			resultProgram.getSymbolTable().getLibrarySymbol(libname + "_conflict1");
		assertNull(conflictSymbol);
	}

	@Test
	public void testAddSameNamespaceNoConflict() throws Exception {

		final String libname = "user32.dll";
		final String namespace = "MyNamespace";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.createNamespace(library, namespace, SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.createNamespace(library, namespace, SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();

		Symbol myNamespaceSymbol = getUniqueSymbol(resultProgram, namespace, externalLibrary);
		assertNotNull(myNamespaceSymbol);
		assertEquals(SymbolType.NAMESPACE, myNamespaceSymbol.getSymbolType());

		Symbol conflictSymbol =
			getUniqueSymbol(resultProgram, "MyNamespace_conflict1", externalLibrary);
		assertNull(conflictSymbol);
	}

	@Test
	public void testSimpleAddSubClassAddSubNamespaceConflict1() throws Exception {

		final String libname = "user32.dll";
		final String namespace1 = "blue";
		final String namespace2 = "green";
		final String class1 = "red";
		final String class2 = "yellow";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace ns =
					mergeProgram.createNamespace(library, namespace1, SourceType.USER_DEFINED);
				assertNotNull(ns);

				ns = mergeProgram.createNamespace(library, namespace2, SourceType.USER_DEFINED);
				assertNotNull(ns);

				ns = mergeProgram.createClass(library, class1, SourceType.USER_DEFINED);
				assertNotNull(ns);

				ns = mergeProgram.createClass(library, class2, SourceType.USER_DEFINED);
				assertNotNull(ns);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace ns =
					mergeProgram.createClass(library, namespace1, SourceType.USER_DEFINED);
				assertNotNull(ns);

				ns = mergeProgram.createClass(library, namespace2, SourceType.USER_DEFINED);
				assertNotNull(ns);

				ns = mergeProgram.createNamespace(library, class1, SourceType.USER_DEFINED);
				assertNotNull(ns);

				ns = mergeProgram.createNamespace(library, class2, SourceType.USER_DEFINED);
				assertNotNull(ns);
			}
		});

		executeMerge(ASK_USER);
		waitForReadTextDialog("Symbol Merge Information", "The following symbols were renamed",
			4000);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		Symbol blue = getUniqueSymbol(resultProgram, namespace1, externalLibrary);
		Symbol blueConflict =
			getUniqueSymbol(resultProgram, namespace1 + "_conflict1", externalLibrary);
		Symbol green = getUniqueSymbol(resultProgram, namespace2, externalLibrary);
		Symbol greenConflict =
			getUniqueSymbol(resultProgram, namespace2 + "_conflict1", externalLibrary);
		Symbol red = getUniqueSymbol(resultProgram, class1, externalLibrary);
		Symbol redConflict = getUniqueSymbol(resultProgram, class1 + "_conflict1", externalLibrary);
		Symbol yellow = getUniqueSymbol(resultProgram, class2, externalLibrary);
		Symbol yellowConflict =
			getUniqueSymbol(resultProgram, class2 + "_conflict1", externalLibrary);
		assertEquals(SymbolType.NAMESPACE, blue.getSymbolType());
		assertEquals(SymbolType.CLASS, blueConflict.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, green.getSymbolType());
		assertEquals(SymbolType.CLASS, greenConflict.getSymbolType());
		assertEquals(SymbolType.CLASS, red.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, redConflict.getSymbolType());
		assertEquals(SymbolType.CLASS, yellow.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, yellowConflict.getSymbolType());
	}

	@Test
	public void testSimpleAddSubClassAddSubNamespaceConflict2() throws Exception {

		final String libname = "user32.dll";
		final String parentNamespace = "MyNamespace";
		final String namespace1 = "blue";
		final String namespace2 = "green";
		final String class1 = "red";
		final String class2 = "yellow";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace parentNS =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);

				Namespace ns =
					mergeProgram.createNamespace(parentNS, namespace1, SourceType.USER_DEFINED);
				assertNotNull(ns);

				ns = mergeProgram.createNamespace(parentNS, namespace2, SourceType.USER_DEFINED);
				assertNotNull(ns);

				ns = mergeProgram.createClass(parentNS, class1, SourceType.USER_DEFINED);
				assertNotNull(ns);

				ns = mergeProgram.createClass(parentNS, class2, SourceType.USER_DEFINED);
				assertNotNull(ns);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace parentNS =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);

				Namespace ns =
					mergeProgram.createClass(parentNS, namespace1, SourceType.USER_DEFINED);
				assertNotNull(ns);

				ns = mergeProgram.createClass(parentNS, namespace2, SourceType.USER_DEFINED);
				assertNotNull(ns);

				ns = mergeProgram.createNamespace(parentNS, class1, SourceType.USER_DEFINED);
				assertNotNull(ns);

				ns = mergeProgram.createNamespace(parentNS, class2, SourceType.USER_DEFINED);
				assertNotNull(ns);
			}
		});

		executeMerge(ASK_USER);
		waitForReadTextDialog("Symbol Merge Information", "The following symbols were renamed",
			4000);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		Namespace myNamespace = (Namespace) getUniqueSymbol(resultProgram, parentNamespace,
			externalLibrary).getObject();
		Symbol blue = getUniqueSymbol(resultProgram, namespace1, myNamespace);
		Symbol blueConflict =
			getUniqueSymbol(resultProgram, namespace1 + "_conflict1", myNamespace);
		Symbol green = getUniqueSymbol(resultProgram, namespace2, myNamespace);
		Symbol greenConflict =
			getUniqueSymbol(resultProgram, namespace2 + "_conflict1", myNamespace);
		Symbol red = getUniqueSymbol(resultProgram, class1, myNamespace);
		Symbol redConflict = getUniqueSymbol(resultProgram, class1 + "_conflict1", myNamespace);
		Symbol yellow = getUniqueSymbol(resultProgram, class2, myNamespace);
		Symbol yellowConflict = getUniqueSymbol(resultProgram, class2 + "_conflict1", myNamespace);
		assertEquals(SymbolType.NAMESPACE, blue.getSymbolType());
		assertEquals(SymbolType.CLASS, blueConflict.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, green.getSymbolType());
		assertEquals(SymbolType.CLASS, greenConflict.getSymbolType());
		assertEquals(SymbolType.CLASS, red.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, redConflict.getSymbolType());
		assertEquals(SymbolType.CLASS, yellow.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, yellowConflict.getSymbolType());
	}

	@Test
	public void testAddSameExternalFunctionNoConflict() throws Exception {

		final String libname = "user32.dll";
		final String parentNamespace = "MyNamespace";
		final String label = "apple";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				mergeProgram.addExternalFunction(namespace, label, address,
					SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				mergeProgram.addExternalFunction(namespace, label, address,
					SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		assertNotNull(externalLibrary);
		Namespace myNamespace = (Namespace) getUniqueSymbol(resultProgram, parentNamespace,
			externalLibrary).getObject();
		assertNotNull(myNamespace);
		Symbol apples = getUniqueSymbol(resultProgram, label, myNamespace);
		Symbol applesConflict = getUniqueSymbol(resultProgram, label + "_conflict1", myNamespace);
		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
		assertNull(applesConflict);
	}

	@Test
	public void testAddNonConflictingExternalLabels() throws Exception {

		final String libname = "user32.dll";
		final String parentNamespace = "MyNamespace";
		final String label1 = "apples";
		final String label2 = "oranges";
		final String address1 = "0x100";
		final String address2 = "0x120";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(namespace, label1, address1,
					SourceType.USER_DEFINED);

			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(namespace, label2, address2,
					SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		assertNotNull(externalLibrary);
		Namespace myNamespace = (Namespace) getUniqueSymbol(resultProgram, parentNamespace,
			externalLibrary).getObject();
		assertNotNull(myNamespace);
		Symbol apples = getUniqueSymbol(resultProgram, label1, myNamespace);
		Symbol oranges = getUniqueSymbol(resultProgram, label2, myNamespace);
		assertEquals(SymbolType.LABEL, apples.getSymbolType());
		assertEquals(SymbolType.LABEL, oranges.getSymbolType());
		ExternalLocation externalLocation = (ExternalLocation) apples.getObject();
		assertEquals(label1, externalLocation.getLabel());
		assertEquals(libname, externalLocation.getLibraryName());
		assertEquals(parentNamespace, externalLocation.getParentName());
		assertEquals(libname + "::" + parentNamespace,
			externalLocation.getParentNameSpace().getName(true));
		assertEquals(null, externalLocation.getFunction());
		assertEquals(libname + "::" + parentNamespace + "::" + label1,
			externalLocation.getSymbol().getName(true));
		assertEquals(SourceType.USER_DEFINED, externalLocation.getSource());
		assertEquals(addr(resultProgram, address1), externalLocation.getAddress());
		ExternalLocation orangesExternalLocation = (ExternalLocation) oranges.getObject();
		assertEquals(label2, orangesExternalLocation.getLabel());
		assertEquals(libname, orangesExternalLocation.getLibraryName());
		assertEquals(parentNamespace, orangesExternalLocation.getParentName());
		assertEquals(libname + "::" + parentNamespace,
			orangesExternalLocation.getParentNameSpace().getName(true));
		assertEquals(null, orangesExternalLocation.getFunction());
		assertEquals(libname + "::" + parentNamespace + "::" + label2,
			orangesExternalLocation.getSymbol().getName(true));
		assertEquals(SourceType.USER_DEFINED, orangesExternalLocation.getSource());
		assertEquals(addr(resultProgram, address2), orangesExternalLocation.getAddress());
	}

	@Test
	public void testAddDiffExternalLabelChooseLatest() throws Exception {
		final String libname = "user32.dll";
		final String parentNamespace = "MyNamespace";
		final String label = "apples";
		final String address1 = "0x100";
		final String address2 = "0x120";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(namespace, label, address1,
					SourceType.USER_DEFINED);

			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(namespace, label, address2,
					SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		assertNotNull(externalLibrary);
		Namespace myNamespace = (Namespace) getUniqueSymbol(resultProgram, parentNamespace,
			externalLibrary).getObject();
		assertNotNull(myNamespace);
		Symbol apples = getUniqueSymbol(resultProgram, label, myNamespace);
		Symbol applesConflict = getUniqueSymbol(resultProgram, label + "_conflict1", myNamespace);
		assertEquals(SymbolType.LABEL, apples.getSymbolType());
		assertNull(applesConflict);
		ExternalLocation externalLocation = (ExternalLocation) apples.getObject();
		assertEquals(label, externalLocation.getLabel());
		assertEquals(libname, externalLocation.getLibraryName());
		assertEquals(parentNamespace, externalLocation.getParentName());
		assertEquals(libname + "::" + parentNamespace,
			externalLocation.getParentNameSpace().getName(true));
		assertEquals(null, externalLocation.getFunction());
		assertEquals(libname + "::" + parentNamespace + "::" + label,
			externalLocation.getSymbol().getName(true));
		assertEquals(SourceType.USER_DEFINED, externalLocation.getSource());
		assertEquals(addr(resultProgram, address1), externalLocation.getAddress());
	}

	@Test
	public void testAddDiffExternalLabelChooseMy() throws Exception {

		final String libname = "user32.dll";
		final String parentNamespace = "MyNamespace";
		final String label = "apples";
		final String address1 = "0x100";
		final String address2 = "0x120";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(namespace, label, address1,
					SourceType.USER_DEFINED);

			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(namespace, label, address2,
					SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", MY_BUTTON);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		assertNotNull(externalLibrary);
		Namespace myNamespace = (Namespace) getUniqueSymbol(resultProgram, parentNamespace,
			externalLibrary).getObject();
		assertNotNull(myNamespace);
		Symbol apples = getUniqueSymbol(resultProgram, label, myNamespace);
		Symbol applesConflict = getUniqueSymbol(resultProgram, label + "_conflict1", myNamespace);
		assertEquals(SymbolType.LABEL, apples.getSymbolType());
		assertNull(applesConflict);
		ExternalLocation externalLocation = (ExternalLocation) apples.getObject();
		assertEquals(label, externalLocation.getLabel());
		assertEquals(libname, externalLocation.getLibraryName());
		assertEquals(parentNamespace, externalLocation.getParentName());
		assertEquals(libname + "::" + parentNamespace,
			externalLocation.getParentNameSpace().getName(true));
		assertEquals(null, externalLocation.getFunction());
		assertEquals(libname + "::" + parentNamespace + "::" + label,
			externalLocation.getSymbol().getName(true));
		assertEquals(SourceType.USER_DEFINED, externalLocation.getSource());
		assertEquals(addr(resultProgram, address2), externalLocation.getAddress());
	}

	@Test
	public void testAddDiffExternalLabelKeepBoth() throws Exception {
		final String libname = "user32.dll";
		final String parentNamespace = "MyNamespace";
		final String label = "apples";
		final String address1 = "0x100";
		final String address2 = "0x120";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(namespace, label, address1,
					SourceType.USER_DEFINED);

			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(namespace, label, address2,
					SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", KEEP_BOTH_BUTTON);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		assertNotNull(externalLibrary);
		Namespace myNamespace =
			resultProgram.getSymbolTable().getNamespace(parentNamespace, externalLibrary);
		assertNotNull(myNamespace);
		SymbolTable symtab = resultProgram.getSymbolTable();

		List<Symbol> symbols = symtab.getSymbols(label, myNamespace);
		assertEquals(2, symbols.size());
		assertTrue(!symbols.get(0).getAddress().equals(symbols.get(1).getAddress()));

	}

	@Test
	public void testAddDiffExternalFunctionKeepLatest() throws Exception {

		final String libname = "user32.dll";
		final String parentNamespace = "MyNamespace";
		final String label = "blue";
		final String address = "0x100";
		final String param1 = "P1";
		final String comment1 = "Test Parameter Comment";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				ExternalLocation externalLocation = mergeProgram.addExternalFunction(namespace,
					label, address, SourceType.USER_DEFINED);

				Function function = externalLocation.getFunction();
				assertNotNull(function);

				Program program = mergeProgram.getProgram();
				Parameter parameter1 = new ParameterImpl(param1, new DWordDataType(), 4, program);
				parameter1.setComment(comment1);

				mergeProgram.updateFunction(function, true, new ByteDataType(), parameter1);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				ExternalLocation externalLocation = mergeProgram.addExternalFunction(namespace,
					label, address, SourceType.USER_DEFINED);

				Function function = externalLocation.getFunction();
				assertNotNull(function);

				Program program = mergeProgram.getProgram();
				Register register = program.getRegister("r0");
				Parameter parameter1 =
					new ParameterImpl("Length", new CharDataType(), register, program);
				parameter1.setComment("Latest Parameter Comment");

				mergeProgram.updateFunction(function, false, new FloatDataType(), parameter1);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		assertNotNull(externalLibrary);
		Namespace myNamespace = (Namespace) getUniqueSymbol(resultProgram, parentNamespace,
			externalLibrary).getObject();
		assertNotNull(myNamespace);
		Symbol apples = getUniqueSymbol(resultProgram, label, myNamespace);
		Symbol applesConflict = getUniqueSymbol(resultProgram, label + "_conflict1", myNamespace);
		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
		assertNull(applesConflict);
		Function function = (Function) apples.getObject();
		assertTrue(new ByteDataType().isEquivalent(function.getReturnType()));
		assertEquals(1, function.getParameterCount());
		Parameter parameter = function.getParameter(0);
		assertEquals(param1, parameter.getName());
		assertTrue(new DWordDataType().isEquivalent(parameter.getDataType()));
		assertTrue(parameter.isStackVariable());
		assertEquals(4, parameter.getStackOffset());
		assertEquals(comment1, parameter.getComment());
	}

	@Test
	public void testAddDiffExternalFunctionKeepMy() throws Exception {

		final String libname = "user32.dll";
		final String parentNamespace = "MyNamespace";
		final String label = "blue";
		final String address = "0x100";
		final String param1 = "P1";
		final String param2 = "Length";
		final String comment1 = "Test Parameter Comment";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				ExternalLocation externalLocation = mergeProgram.addExternalFunction(namespace,
					label, address, SourceType.USER_DEFINED);

				Function function = externalLocation.getFunction();
				assertNotNull(function);

				Program program = mergeProgram.getProgram();
				Parameter parameter1 = new ParameterImpl(param1, new DWordDataType(), 4, program);
				parameter1.setComment(comment1);

				mergeProgram.updateFunction(function, true, new ByteDataType(), parameter1);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				ExternalLocation externalLocation = mergeProgram.addExternalFunction(namespace,
					label, address, SourceType.USER_DEFINED);

				Function function = externalLocation.getFunction();
				assertNotNull(function);

				Program program = mergeProgram.getProgram();
				Register register = program.getRegister("r0");
				Parameter parameter1 =
					new ParameterImpl(param2, new CharDataType(), register, program);
				parameter1.setComment("Latest Parameter Comment");

				mergeProgram.updateFunction(function, true, new FloatDataType(), parameter1);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", MY_BUTTON);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		assertNotNull(externalLibrary);
		Namespace myNamespace = (Namespace) getUniqueSymbol(resultProgram, parentNamespace,
			externalLibrary).getObject();
		assertNotNull(myNamespace);
		Symbol apples = getUniqueSymbol(resultProgram, label, myNamespace);
		Symbol applesConflict = getUniqueSymbol(resultProgram, label + "_conflict1", myNamespace);
		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
		assertNull(applesConflict);
		Function function = (Function) apples.getObject();
		checkFunctionReturnType(function, new FloatDataType());
		assertTrue(new FloatDataType().isEquivalent(function.getReturnType()));
		assertEquals(1, function.getParameterCount());
		Parameter parameter = function.getParameter(0);
		assertEquals(param2, parameter.getName());
		assertTrue(new CharDataType().isEquivalent(parameter.getDataType()));
		assertTrue(parameter.isRegisterVariable());
		Register baseRegister = parameter.getRegister().getBaseRegister();
		Register register = resultProgram.getRegister("r0");
		assertTrue(baseRegister.contains(register));
		assertEquals("Latest Parameter Comment", parameter.getComment());
	}

	@Test
	public void testAddDiffExternalFunctionKeepBoth() throws Exception {
		final String libname = "user32.dll";
		final String parentNamespace = "MyNamespace";
		final String label1 = "oranges";
		final String label2 = "apples";
		final String address = null;
		final String param1 = "P1";
		final String param2 = "Length";
		final String comment1 = "Test Parameter Comment";
		final String comment2 = "My Parameter Comment";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				mergeProgram.addExternalFunction(namespace, label1, "0x120",
					SourceType.USER_DEFINED);
				ExternalLocation externalLocation = mergeProgram.addExternalFunction(namespace,
					label2, address, SourceType.USER_DEFINED);

				Function function = externalLocation.getFunction();
				assertNotNull(function);

				Program program = mergeProgram.getProgram();
				Parameter parameter1 = new ParameterImpl(param1, new DWordDataType(), 4, program);
				parameter1.setComment(comment1);

				mergeProgram.updateFunction(function, true, new ByteDataType(), parameter1);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				ExternalLocation externalLocation = mergeProgram.addExternalFunction(namespace,
					label2, address, SourceType.USER_DEFINED);

				Function function = externalLocation.getFunction();
				assertNotNull(function);

				Program program = mergeProgram.getProgram();
				Register register = program.getRegister("r0l");
				Parameter parameter1 =
					new ParameterImpl(param2, new CharDataType(), register, program);
				parameter1.setComment(comment2);

				mergeProgram.updateFunction(function, true, new FloatDataType(), parameter1);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", KEEP_BOTH_BUTTON);
		waitForMergeCompletion();

		SymbolTable symbolTable = resultProgram.getSymbolTable();
		Namespace externalLibrary = (Namespace) symbolTable.getLibrarySymbol(libname).getObject();
		assertNotNull(externalLibrary);
		Namespace myNamespace = symbolTable.getNamespace(parentNamespace, externalLibrary);
		assertNotNull(myNamespace);

		Symbol oranges = getUniqueSymbol(resultProgram, label1, myNamespace);
		assertNotNull(oranges);

		List<Symbol> symbols = symbolTable.getSymbols(label2, myNamespace);
		assertEquals(2, symbols.size());
		Object obj1 = symbols.get(0).getObject();
		Object obj2 = symbols.get(1).getObject();
		assertTrue(obj1 instanceof Function);
		assertTrue(obj2 instanceof Function);
		Function fun1 = (Function) obj1;
		Function fun2 = (Function) obj2;

		if (!fun1.getReturnType().isEquivalent(new ByteDataType())) {
			Function tmp = fun1;
			fun1 = fun2;
			fun2 = tmp;
		}

		assertTrue(new ByteDataType().isEquivalent(fun1.getReturnType()));
		assertEquals(1, fun1.getParameterCount());
		Parameter parameter = fun1.getParameter(0);
		assertEquals(param1, parameter.getName());
		assertTrue(new DWordDataType().isEquivalent(parameter.getDataType()));
		assertTrue(parameter.isStackVariable());
		assertEquals(4, parameter.getStackOffset());
		assertEquals(comment1, parameter.getComment());

		assertTrue(new FloatDataType().isEquivalent(fun2.getReturnType()));
		assertEquals(1, fun2.getParameterCount());
		Parameter f2parameter = fun2.getParameter(0);
		assertEquals(param2, f2parameter.getName());
		assertTrue(new CharDataType().isEquivalent(f2parameter.getDataType()));
		assertTrue(f2parameter.isRegisterVariable());
		assertEquals(resultProgram.getRegister("r0l"), f2parameter.getRegister());
		assertEquals(comment2, f2parameter.getComment());
	}

	@Test
	public void testAddDiffExternalFunction2ChooseLatest() throws Exception {
		final String libname = "user32.dll";
		final String parentNamespace = "MyNamespace";
		final String label = "blue";
		final String address = "0x100";
		final String param1 = "P1";
		final String param2 = "Length";
		final String comment1 = "Test Parameter Comment";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				ExternalLocation externalLocation = mergeProgram.addExternalFunction(namespace,
					label, address, SourceType.USER_DEFINED);

				Function function = externalLocation.getFunction();
				assertNotNull(function);

				Program program = mergeProgram.getProgram();
				Parameter parameter1 = new ParameterImpl(param1, new DWordDataType(), 4, program);
				parameter1.setComment(comment1);

				mergeProgram.updateFunction(function, true, new ByteDataType(), parameter1);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				ExternalLocation externalLocation = mergeProgram.addExternalFunction(namespace,
					label, address, SourceType.USER_DEFINED);

				Function function = externalLocation.getFunction();
				assertNotNull(function);

				Program program = mergeProgram.getProgram();
				Register register = program.getRegister("r0");
				Parameter parameter1 =
					new ParameterImpl(param2, new CharDataType(), register, program);
				parameter1.setComment("Latest Parameter Comment");

				mergeProgram.updateFunction(function, false, new FloatDataType(), parameter1);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		assertNotNull(externalLibrary);
		Namespace myNamespace = (Namespace) getUniqueSymbol(resultProgram, parentNamespace,
			externalLibrary).getObject();
		assertNotNull(myNamespace);
		Symbol apples = getUniqueSymbol(resultProgram, label, myNamespace);
		Symbol applesConflict = getUniqueSymbol(resultProgram, label + "_conflict1", myNamespace);
		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
		assertNull(applesConflict);
		Function function = (Function) apples.getObject();
		checkFunctionReturnType(function, new ByteDataType());
		assertEquals(1, function.getParameterCount());
		Parameter parameter = function.getParameter(0);
		assertEquals(param1, parameter.getName());
		assertEquals(comment1, parameter.getComment());
		checkParameterDataType(parameter, new DWordDataType());
		assertTrue(parameter.isStackVariable());
	}

	@Test
	public void testAddDiffExternalFunction2ChooseMy() throws Exception {
		final String libname = "user32.dll";
		final String parentNamespace = "MyNamespace";
		final String label = "blue";
		final String address = "0x100";
		final String param1 = "P1";
		final String param2 = "Length";
		final String comment1 = "Test Parameter Comment";
		final String comment2 = "Latest Parameter Comment";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				ExternalLocation externalLocation = mergeProgram.addExternalFunction(namespace,
					label, address, SourceType.USER_DEFINED);

				Function function = externalLocation.getFunction();
				assertNotNull(function);

				Program program = mergeProgram.getProgram();
				Parameter parameter1 = new ParameterImpl(param1, new DWordDataType(), 4, program);
				parameter1.setComment(comment1);

				mergeProgram.updateFunction(function, true, new ByteDataType(), parameter1);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				ExternalLocation externalLocation = mergeProgram.addExternalFunction(namespace,
					label, address, SourceType.USER_DEFINED);

				Function function = externalLocation.getFunction();
				assertNotNull(function);

				Program program = mergeProgram.getProgram();
				Register register = program.getRegister("r12l");
				Parameter parameter1 =
					new ParameterImpl(param2, new CharDataType(), register, program);
				parameter1.setComment(comment2);

				mergeProgram.updateFunction(function, false, new FloatDataType(), parameter1);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", MY_BUTTON);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		assertNotNull(externalLibrary);
		Namespace myNamespace = (Namespace) getUniqueSymbol(resultProgram, parentNamespace,
			externalLibrary).getObject();
		assertNotNull(myNamespace);
		Symbol apples = getUniqueSymbol(resultProgram, label, myNamespace);
		Symbol applesConflict = getUniqueSymbol(resultProgram, label + "_conflict1", myNamespace);
		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
		assertNull(applesConflict);
		Function function = (Function) apples.getObject();
		checkFunctionReturnType(function, new FloatDataType());
		assertEquals(1, function.getParameterCount());
		Parameter parameter = function.getParameter(0);
		assertEquals(param2, parameter.getName());
		assertEquals(comment2, parameter.getComment());
		checkParameterDataType(parameter, new CharDataType());
		assertTrue(parameter.isRegisterVariable());
		assertEquals("r12l", parameter.getRegister().getName());
	}

	@Test
	public void testAddDiffExternalFunction2KeepBoth() throws Exception {
		final String libname = "user32.dll";
		final String parentNamespace = "MyNamespace";
		final String label = "blue";
		final String address = null;
		final String param1 = "P1";
		final String param2 = "Length";
		final String comment1 = "Test Parameter Comment";
		final String comment2 = "Latest Parameter Comment";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				ExternalLocation externalLocation = mergeProgram.addExternalFunction(namespace,
					label, address, SourceType.USER_DEFINED);

				Function function = externalLocation.getFunction();
				assertNotNull(function);

				Program program = mergeProgram.getProgram();
				Parameter parameter1 = new ParameterImpl(param1, new DWordDataType(), 4, program);
				parameter1.setComment(comment1);

				mergeProgram.updateFunction(function, true, new ByteDataType(), parameter1);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, parentNamespace, SourceType.USER_DEFINED);
				ExternalLocation externalLocation = mergeProgram.addExternalFunction(namespace,
					label, address, SourceType.USER_DEFINED);

				Function function = externalLocation.getFunction();
				assertNotNull(function);

				Program program = mergeProgram.getProgram();
				Register register = program.getRegister("r12l");
				Parameter parameter1 =
					new ParameterImpl(param2, new CharDataType(), register, program);
				parameter1.setComment(comment2);

				mergeProgram.updateFunction(function, false, new FloatDataType(), parameter1);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", KEEP_BOTH_BUTTON);
		waitForMergeCompletion();

		SymbolTable symbolTable = resultProgram.getSymbolTable();
		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		assertNotNull(externalLibrary);
		Namespace myNamespace = (Namespace) getUniqueSymbol(resultProgram, parentNamespace,
			externalLibrary).getObject();

		List<Symbol> symbols = symbolTable.getSymbols(label, myNamespace);
		assertEquals(2, symbols.size());
		Object obj1 = symbols.get(0).getObject();
		Object obj2 = symbols.get(1).getObject();
		assertTrue(obj1 instanceof Function);
		assertTrue(obj2 instanceof Function);
		Function fun1 = (Function) obj1;
		Function fun2 = (Function) obj2;

		if (!fun1.getReturnType().isEquivalent(new ByteDataType())) {
			Function tmp = fun1;
			fun1 = fun2;
			fun2 = tmp;
		}

		assertTrue(new ByteDataType().isEquivalent(fun1.getReturnType()));
		assertEquals(1, fun1.getParameterCount());
		Parameter parameter = fun1.getParameter(0);
		assertEquals(param1, parameter.getName());
		assertTrue(new DWordDataType().isEquivalent(parameter.getDataType()));
		assertTrue(parameter.isStackVariable());
		assertEquals(4, parameter.getStackOffset());
		assertEquals(comment1, parameter.getComment());

		assertTrue(new FloatDataType().isEquivalent(fun2.getReturnType()));
		assertEquals(1, fun2.getParameterCount());
		Parameter f2parameter = fun2.getParameter(0);
		assertEquals(param2, f2parameter.getName());
		assertTrue(new CharDataType().isEquivalent(f2parameter.getDataType()));
		assertTrue(f2parameter.isRegisterVariable());
		assertEquals("r12l", f2parameter.getRegister().getName());
		assertEquals(comment2, f2parameter.getComment());

//
//		assertNotNull(myNamespace);
//		SymbolTable symtab = resultProgram.getSymbolTable();
//		Symbol apples = getUniqueSymbol(resultProgram,label, myNamespace);
//		assertNotNull(apples);
//		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
//		Function function = (Function) apples.getObject();
//		checkFunctionReturnType(function, new ByteDataType());
//		assertEquals(1, function.getParameterCount());
//		Parameter parameter = function.getParameter(0);
//		assertEquals(param1, parameter.getName());
//		assertEquals(comment1, parameter.getComment());
//		checkParameterDataType(parameter, new DWordDataType());
//		assertTrue(parameter.isStackVariable());
//
//		Symbol applesConflict = getUniqueSymbol(resultProgram,label + "_conflict1", myNamespace);
//		assertNotNull(applesConflict);
//		assertEquals(SymbolType.FUNCTION, applesConflict.getSymbolType());
//		Function conflictFunction = (Function) applesConflict.getObject();
//		checkFunctionReturnType(conflictFunction, new FloatDataType());
//		assertEquals(1, conflictFunction.getParameterCount());
//		Parameter conflictParameter = conflictFunction.getParameter(0);
//		assertEquals(param2, conflictParameter.getName());
//		assertEquals(comment2, conflictParameter.getComment());
//		checkParameterDataType(conflictParameter, new CharDataType());
//		assertTrue(conflictParameter.isRegisterVariable());
//		assertEquals("r12", conflictParameter.getRegister().getName());
//

	}

	@Test
	public void testAddExternalLocationVersusNamespaceNoConflict() throws Exception {

		final String libname = "user32.dll";
		final String label = "Foo";
		final String address = "0x100";

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				mergeProgram.addExternalLocation(library, label, address, new DoubleDataType(),
					SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				Library library =
					mergeProgram.createExternalLibrary(libname, SourceType.USER_DEFINED);
				Namespace namespace =
					mergeProgram.createNamespace(library, label, SourceType.USER_DEFINED);
				assertNotNull(namespace);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		assertNotNull(externalLibrary);

		Symbol namespaceSymbol =
			resultProgram.getSymbolTable().getNamespaceSymbol(label, externalLibrary);
		assertNotNull(namespaceSymbol);

		List<Symbol> symbols = resultProgram.getSymbolTable().getSymbols(label, externalLibrary);
		assertEquals(2, symbols.size());
		Symbol otherSymbol = symbols.get(0) == namespaceSymbol ? symbols.get(1) : symbols.get(0);
		Object object = otherSymbol.getObject();
		assertTrue(object instanceof ExternalLocation);
		ExternalLocation locationFoo = (ExternalLocation) object;
		checkExternalDataType(locationFoo, new DoubleDataType());
	}

	@Test
	public void testAddSameLabelDiffDataTypeKeepBoth() throws Exception {

		final String libname = "MyLibrary";
		final String label = "blue";
		final String address = null;
		final String[] BLUE_PATH = new String[] { libname, label };
		final CategoryPath catPath = new CategoryPath("/cat1");
		final Structure myStruct = new StructureDataType(catPath, "MyStruct", 0);
		myStruct.add(new WordDataType());
		myStruct.add(new FloatDataType());
		final TypedefDataType myTypedef = new TypedefDataType("MyTypedef", myStruct);

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				createExternalLabel(mergeProgram, BLUE_PATH, address, myStruct,
					SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation = getExternalLocation(program, BLUE_PATH);
				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				checkDataType(myStruct, externalLocation.getDataType());
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				createExternalLabel(mergeProgram, BLUE_PATH, address, myTypedef,
					SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation = getExternalLocation(program, BLUE_PATH);
				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				checkDataType(myTypedef, externalLocation.getDataType());
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", KEEP_BOTH_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();
		SymbolTable symtab = resultProgram.getSymbolTable();

		List<Symbol> symbols = symtab.getSymbols(label, externalLibrary);
		assertEquals(2, symbols.size());
		ExternalLocation loc1 = (ExternalLocation) symbols.get(0).getObject();
		ExternalLocation loc2 = (ExternalLocation) symbols.get(1).getObject();
		DataType type1 = loc1.getDataType();
		DataType type2 = loc2.getDataType();

		if (type1.isEquivalent(myStruct)) {
			checkDataType(myTypedef, type2);
		}
		else {
			checkDataType(myTypedef, type1);
			checkDataType(myStruct, type2);
		}
	}

	@Test
	public void testAddSameLabelDiffDataTypeKeepLatest() throws Exception {

		final String libname = "MyLibrary";
		final String label = "blue";
		final String address = "0x100";
		final String[] BLUE_PATH = new String[] { libname, label };
		final CategoryPath catPath = new CategoryPath("/cat1");
		final Structure myStruct = new StructureDataType(catPath, "MyStruct", 0);
		myStruct.add(new WordDataType());
		myStruct.add(new FloatDataType());
		final TypedefDataType myTypedef = new TypedefDataType("MyTypeDef", myStruct);

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				createExternalLabel(mergeProgram, BLUE_PATH, address, myStruct,
					SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation = getExternalLocation(program, BLUE_PATH);
				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				checkDataType(myStruct, externalLocation.getDataType());
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				createExternalLabel(mergeProgram, BLUE_PATH, address, myTypedef,
					SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation = getExternalLocation(program, BLUE_PATH);
				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				checkDataType(myTypedef, externalLocation.getDataType());
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();

		SymbolTable symtab = resultProgram.getSymbolTable();

		List<Symbol> symbols = symtab.getSymbols(label, externalLibrary);
		assertEquals(1, symbols.size());
		Symbol blue = symbols.get(0);
		assertEquals(SymbolType.LABEL, blue.getSymbolType());
		assertTrue(blue.isExternal());
		ExternalLocation externalLocation = externalManager.getExternalLocation(blue);
		assertNotNull(externalLocation);
		assertEquals(libname, externalLocation.getLibraryName());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(false, externalLocation.isFunction());
		checkDataType(myStruct, externalLocation.getDataType());
	}

	@Test
	public void testAddSameLabelDiffDataTypeKeepMy() throws Exception {

		final String libname = "MyLibrary";
		final String label = "blue";
		final String address = "0x100";
		final String[] BLUE_PATH = new String[] { libname, label };
		final CategoryPath catPath = new CategoryPath("/cat1");
		final Structure myStruct = new StructureDataType(catPath, "MyStruct", 0);
		myStruct.add(new WordDataType());
		myStruct.add(new FloatDataType());
		final TypedefDataType myTypedef = new TypedefDataType("MyStruct", myStruct);

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				createExternalLabel(mergeProgram, BLUE_PATH, address, myStruct,
					SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation = getExternalLocation(program, BLUE_PATH);
				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				checkDataType(myStruct, externalLocation.getDataType());
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				createExternalLabel(mergeProgram, BLUE_PATH, address, myTypedef,
					SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation = getExternalLocation(program, BLUE_PATH);
				assertNotNull(externalLocation);
				assertEquals(false, externalLocation.isFunction());

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				checkDataType(myTypedef, externalLocation.getDataType());
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));
		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol(libname).getObject();

		SymbolTable symtab = resultProgram.getSymbolTable();

		List<Symbol> symbols = symtab.getSymbols(label, externalLibrary);
		assertEquals(1, symbols.size());
		Symbol blue = symbols.get(0);
		assertEquals(SymbolType.LABEL, blue.getSymbolType());
		assertTrue(blue.isExternal());
		ExternalLocation externalLocation = externalManager.getExternalLocation(blue);
		assertNotNull(externalLocation);
		assertEquals(libname, externalLocation.getLibraryName());
		assertEquals(addr(resultProgram, address), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		assertEquals(false, externalLocation.isFunction());
		checkDataType(myTypedef, externalLocation.getDataType());
	}

	void createExternalLabel(MergeProgram mergeProgram, String[] path, String memoryAddress,
			DataType dt, SourceType sourceType) {

		int nameIndex = path.length - 1;
		Library currentLibrary = null;
		for (int i = 0; i < nameIndex; i++) {
			currentLibrary = mergeProgram.createExternalLibrary(path[i], sourceType);
		}

		mergeProgram.addExternalLocation(currentLibrary, path[nameIndex], memoryAddress, dt,
			sourceType);
	}

	@Test
	public void testExternalAddDontUseForAll() throws Exception {

		final String libname = "advapi32.dll";
		final String label = "printf";
		final String address1 = "0x100";
		final String address2 = "0x110";
		final String libnameA = "MyLibrary";
		final String labelA = "blue";
		final String[] BLUE_PATH = new String[] { libnameA, labelA };
		final CategoryPath catPath = new CategoryPath("/cat1");
		final Structure myStruct = new StructureDataType(catPath, "MyStruct", 0);
		myStruct.add(new WordDataType());
		myStruct.add(new FloatDataType());
		final TypedefDataType myTypedef = new TypedefDataType("MyStruct", myStruct);

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, address1, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address1), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());

				createExternalLabel(mergeProgram, BLUE_PATH, null, myStruct,
					SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, address2, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address2), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());

				createExternalLabel(mergeProgram, BLUE_PATH, null, myTypedef,
					SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict",
			ExternalFunctionMerger.KEEP_BOTH_BUTTON_NAME, false);

		chooseButtonAndApply("Resolve External Add Conflict",
			ExternalFunctionMerger.KEEP_BOTH_BUTTON_NAME, false);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));

		List<ExternalLocation> externalLocations =
			externalManager.getExternalLocations(libname, label);
		assertEquals(2, externalLocations.size());

		List<ExternalLocation> externalLocations2 =
			externalManager.getExternalLocations(BLUE_PATH[0], BLUE_PATH[1]);
		assertEquals(2, externalLocations2.size());
	}

	@Test
	public void testExternalAddUseForAll() throws Exception {
		final String libname = "advapi32.dll";
		final String label = "printf";
		final String address1 = "0x100";
		final String address2 = "0x110";
		final String libnameA = "MyLibrary";
		final String labelA = "blue";
		final String[] BLUE_PATH = new String[] { libnameA, labelA };
		final CategoryPath catPath = new CategoryPath("/cat1");
		final Structure myStruct = new StructureDataType(catPath, "MyStruct", 0);
		myStruct.add(new WordDataType());
		myStruct.add(new FloatDataType());
		final TypedefDataType myTypedef = new TypedefDataType("MyStruct", myStruct);

		mtf.initialize("NotepadMergeListingTest", new MergeProgramModifier() {

			@Override
			public void initializeProgram(MergeProgram program) throws Exception {
				program.addMemory("memory", "0x0", 0x200);
			}

			@Override
			public void modifyLatest(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, address1, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address1), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());

				createExternalLabel(mergeProgram, BLUE_PATH, null, myStruct,
					SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(MergeProgram mergeProgram) throws Exception {
				mergeProgram.addExternalLocation(libname, label, address2, SourceType.USER_DEFINED);

				Program program = mergeProgram.getProgram();
				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains(libname));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation(libname, label);
				assertNotNull(externalLocation);

				assertEquals(libname + "::" + label, externalLocation.toString());
				assertEquals(addr(program, address2), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
				assertEquals(false, externalLocation.isFunction());

				createExternalLabel(mergeProgram, BLUE_PATH, null, myTypedef,
					SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict",
			ExternalFunctionMerger.KEEP_BOTH_BUTTON_NAME, true);

		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains(libname));

		List<ExternalLocation> externalLocations =
			externalManager.getExternalLocations(libname, label);
		assertEquals(2, externalLocations.size());

		List<ExternalLocation> externalLocations2 =
			externalManager.getExternalLocations(BLUE_PATH[0], BLUE_PATH[1]);
		assertEquals(2, externalLocations2.size());
	}

}
