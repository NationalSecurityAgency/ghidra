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
package ghidra.program.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.program.database.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Test the Diff of thunk functions.
 */
public class ExternalFunctionDiffTest extends AbstractGhidraHeadedIntegrationTest {

	private final static String THUNK_A_ENTRY = "0100199b";
	private final static String THUNK_A_END = "010019a1";
	private final static String THUNK_A_ALTERNATE_END = "010019c3";
	private final static String FUNCTION_1 = "0100248f";
	private final static String FUNCTION_2 = "010033f6";
	private final static String FUNCTION_3 = "01003bed";

	private MergeTestFacilitator mtf;

	private Program latestProgram;
	private Program myProgram;

	public ExternalFunctionDiffTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		// This has the four programs for the merge.
		fixupGUI();
		mtf = new MergeTestFacilitator();
		TestEnv testEnv = mtf.getTestEnvironment();
		testEnv.getTool().setToolName("TestTool");
	}

	@After
	public void tearDown() throws Exception {

		// In case a test failed we need to cancel the merge,
		// since the merge window may still be on the screen.

		try {
			if (latestProgram != null) {
				latestProgram.flushEvents();
			}
			if (myProgram != null) {
				myProgram.flushEvents();
			}
			waitForPostedSwingRunnables();

		}
		catch (Exception e) {
			e.printStackTrace();
		}

		try {
			latestProgram = null;
			myProgram = null;
			mtf.dispose(); // Get rid of the merge environment.
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	void sleep(int timeMS) {
		try {
			Thread.sleep(timeMS);
		}
		catch (InterruptedException e) {
			// Do nothing.
		}
	}

	@Test
	public void testExtLabelRefAddSame() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
						RefType.DATA);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
						RefType.DATA);

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

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSet expectedDifferences = new AddressSet();
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(latestProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);
		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);
	}

	@Test
	public void testExtLabelRefAddDiff() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1006674"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1006674"), "advapi32.dll",
						"oranges", null, SourceType.USER_DEFINED, 0, RefType.DATA);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1006674"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1006674"), "advapi32.dll",
						"apples", null, SourceType.USER_DEFINED, 0, RefType.DATA);

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

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSet expectedRefDifferences =
			new AddressSet(addr(latestProgram, "0x1006674"), addr(latestProgram, "0x1006677"));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(latestProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedRefDifferences, differences);
		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSet expectedFunctionDifferences = new AddressSet();
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedFunctionDifferences, functionDifferences);
	}

//	public void testExternalAddDiffConflict() throws Exception {
//
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyLatest(ProgramDB program) {
//				int txId = program.startTransaction("Modify Latest Program");
//				boolean commit = false;
//				try {
//					ExternalManager externalManager = program.getExternalManager();
//					ExternalLocation externalFunctionLoc =
//						externalManager.addExtFunction("testLib", "apples", (Address) null,
//							SourceType.USER_DEFINED);
//
//					commit = true;
//				}
//				catch (Exception e) {
//					Assert.fail(e.getMessage());
//				}
//				finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyPrivate(ProgramDB program) {
//				int txId = program.startTransaction("Modify My Program");
//				boolean commit = false;
//				try {
//					ExternalManager externalManager = program.getExternalManager();
//					ExternalLocation externalFunctionLoc =
//						externalManager.addExtFunction("testLib", "oranges", (Address) null,
//							SourceType.USER_DEFINED);
//
//					commit = true;
//				}
//				catch (Exception e) {
//					Assert.fail(e.getMessage());
//				}
//				finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//		});
//
//		latestProgram = mtf.getLatestProgram();
//		myProgram = mtf.getPrivateProgram();
//
//		AddressSet expectedDifferences = new AddressSet(latestProgram.getAddressFactory());
//		expectedDifferences.addRange(addr(latestProgram, ), addr());
//		// Perform the Diff and check the differences.
//		ProgramDiff programDiff = new ProgramDiff(latestProgram, myProgram);
//		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
//		assertEquals(expectedDifferences, differences);
//		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
//		AddressSetView functionDifferences =
//			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
//		assertEquals(expectedDifferences, functionDifferences);
//	}

	@Test
	public void testAddSameThunkNoConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, FUNCTION_1));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, FUNCTION_1));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Private program.");
					}
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

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSet expectedDifferences = new AddressSet();
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(latestProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);
		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);
	}

	@Test
	public void testAddDifferentThunkAtSameSpot() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, FUNCTION_3));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, FUNCTION_1));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Private program.");
					}
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

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSet expectedDifferences =
			new AddressSet(addr(latestProgram, THUNK_A_ENTRY), addr(latestProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(latestProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);
		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);
	}

	@Test
	public void testAddThunkToJustLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, FUNCTION_3));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// Do nothing. Only wanted thunk added to Latest.
			}
		});

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSet expectedDifferences =
			new AddressSet(addr(latestProgram, THUNK_A_ENTRY), addr(latestProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(latestProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);
		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);
	}

	@Test
	public void testAddThunkToJustMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Do nothing. Only wanted thunk added to My.
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, FUNCTION_3));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}
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

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSet expectedDifferences =
			new AddressSet(addr(latestProgram, THUNK_A_ENTRY), addr(latestProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(latestProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);
		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);
	}

	@Test
	public void testAddDifferentBodyThunk() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, FUNCTION_1));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function =
					program.getFunctionManager().getFunctionAt(addr(program, THUNK_A_ENTRY));
				assertNotNull(function);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body = new AddressSet(addr(program, THUNK_A_ENTRY),
						addr(program, THUNK_A_ALTERNATE_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, FUNCTION_1));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Private program.");
					}
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function =
					program.getFunctionManager().getFunctionAt(addr(program, THUNK_A_ENTRY));
				assertNotNull(function);
			}
		});

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSet expectedDifferences =
			new AddressSet(addr(latestProgram, THUNK_A_ENTRY), addr(latestProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(latestProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter functionFilter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(functionFilter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);
	}

	@Test
	public void testAddThunksWithBodyOverlap() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, FUNCTION_1));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function =
					program.getFunctionManager().getFunctionAt(addr(program, THUNK_A_ENTRY));
				assertNotNull(function);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body = new AddressSet(addr(program, "0100199b"),
						addr(program, THUNK_A_ALTERNATE_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, "0100199b"), body, addr(program, FUNCTION_1));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Private program.");
					}
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function =
					program.getFunctionManager().getFunctionAt(addr(program, "0100199b"));
				assertNotNull(function);
			}
		});

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSet expectedDifferences =
			new AddressSet(addr(latestProgram, THUNK_A_ENTRY), addr(latestProgram, THUNK_A_ENTRY));
		expectedDifferences.addRange(addr(latestProgram, "0100199b"),
			addr(latestProgram, "0100199b"));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(latestProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter functionFilter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(functionFilter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);
	}

	@Test
	public void testChangeThunkPointedToDifferentlyInEach() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Setup Original Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, FUNCTION_3));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					FunctionManager functionManager = program.getFunctionManager();
					Function thunkFunction =
						functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					Function referredToFunction =
						functionManager.getFunctionAt(addr(program, FUNCTION_2));
					assertNotNull(thunkFunction);
					assertNotNull(referredToFunction);
					thunkFunction.setThunkedFunction(referredToFunction);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					FunctionManager functionManager = program.getFunctionManager();
					Function thunkFunction =
						functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					Function referredToFunction =
						functionManager.getFunctionAt(addr(program, FUNCTION_1));
					assertNotNull(thunkFunction);
					assertNotNull(referredToFunction);
					thunkFunction.setThunkedFunction(referredToFunction);
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

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSet expectedDifferences =
			new AddressSet(addr(latestProgram, THUNK_A_ENTRY), addr(latestProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(latestProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);
		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);
	}

	@Test
	public void testChangeThunkBodyDifferentlyInLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Setup Original Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, FUNCTION_3));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					FunctionManager functionManager = program.getFunctionManager();
					Function thunkFunction =
						functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					assertNotNull(thunkFunction);

					AddressSet body = new AddressSet(addr(program, THUNK_A_ENTRY),
						addr(program, THUNK_A_ALTERNATE_END));
					thunkFunction.setBody(body);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// Nothing to do. Only Latest is being changed.
			}
		});

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSet expectedDifferences =
			new AddressSet(addr(latestProgram, THUNK_A_ENTRY), addr(latestProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(latestProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);
		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);
	}

	@Test
	public void testChangeThunkBodyDifferentlyInMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Setup Original Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, FUNCTION_3));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				// Nothing to do. Only Latest is being changed.
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					FunctionManager functionManager = program.getFunctionManager();
					Function thunkFunction =
						functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					assertNotNull(thunkFunction);

					AddressSet body = new AddressSet(addr(program, THUNK_A_ENTRY),
						addr(program, THUNK_A_ALTERNATE_END));
					thunkFunction.setBody(body);
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

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSet expectedDifferences =
			new AddressSet(addr(latestProgram, THUNK_A_ENTRY), addr(latestProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(latestProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);
		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);
	}

	@Test
	public void testAddThunkVsNonThunk() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body = new AddressSet(addr(program, THUNK_A_ENTRY),
						addr(program, THUNK_A_ALTERNATE_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, "0100199b"), body, addr(program, FUNCTION_1));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk function in Latest program.");
					}
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function =
					program.getFunctionManager().getFunctionAt(addr(program, THUNK_A_ENTRY));
				assertNotNull(function);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body = new AddressSet(addr(program, THUNK_A_ENTRY),
						addr(program, THUNK_A_ALTERNATE_END));
					CreateFunctionCmd cmd = new CreateFunctionCmd(null, addr(program, "0100199b"),
						body, SourceType.USER_DEFINED);
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create non-thunk function in Private program.");
					}
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function =
					program.getFunctionManager().getFunctionAt(addr(program, THUNK_A_ENTRY));
				assertNotNull(function);
			}
		});

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSet expectedDifferences =
			new AddressSet(addr(latestProgram, THUNK_A_ENTRY), addr(latestProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(latestProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter functionFilter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(functionFilter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);
	}

	@Test
	public void testAddSameThunksDifferentOrder() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					ExternalLocation extFun1 = program.getExternalManager().addExtFunction(
						"EXT_LIB", "EXT_FUN1", null, SourceType.IMPORTED);
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, extFun1.getExternalSpaceAddress());
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}
					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ExternalLocation extFunx = program.getExternalManager().addExtFunction(
						"EXT_LIB", "EXT_FUNX", null, SourceType.IMPORTED);
					ExternalLocation extFun1 = program.getExternalManager().addExtFunction(
						"EXT_LIB", "EXT_FUN1", null, SourceType.IMPORTED);
					extFun1.setName(extFun1.getParentNameSpace(), "DEMANGLED", SourceType.ANALYSIS);
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, extFun1.getExternalSpaceAddress());
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSet expectedDifferences = new AddressSet();
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(latestProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);
		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);
	}

	//**************************
	// Helper methods.
	//**************************

	private Address addr(Program program, String address) {
		return program.getAddressFactory().getAddress(address);
	}
}
