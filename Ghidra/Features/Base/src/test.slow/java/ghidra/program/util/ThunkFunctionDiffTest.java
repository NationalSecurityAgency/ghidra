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

import static org.junit.Assert.*;

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

public class ThunkFunctionDiffTest extends AbstractGhidraHeadedIntegrationTest {

	private final static String THUNK_A_ENTRY = "0100199b";
	private final static String THUNK_A_END = "010019a1";
	private final static String THUNK_A_ALTERNATE_END = "010019c3";
	private final static String FUNCTION_1 = "0100248f";
	private final static String FUNCTION_2 = "010033f6";
	private final static String FUNCTION_3 = "01003bed";

	private MergeTestFacilitator mtf;

	private Program latestProgram;
	private Program myProgram;

	public ThunkFunctionDiffTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		// Creates the Version Merge for tests.
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
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateFunctionCmd cmd = new CreateFunctionCmd(null,
						addr(program, THUNK_A_ENTRY), body, SourceType.USER_DEFINED);
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
	public void testThunkToFunctionVersusExternalFunction() throws Exception {

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
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);

					// Create a thunk to the external function.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, function.getEntryPoint());
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
		FunctionManager latestFM = latestProgram.getFunctionManager();
		FunctionManager myFM = myProgram.getFunctionManager();

		Namespace externalLibrary = (Namespace) getUniqueSymbol(myProgram, "user32.dll",
			myProgram.getGlobalNamespace()).getObject();
		assertNotNull(externalLibrary);
		Symbol apples = getUniqueSymbol(myProgram, "apples", externalLibrary);
		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
		Function myExternalFunction = (Function) apples.getObject();
		Function latestThunked = latestFM.getFunctionAt(addr(latestProgram, FUNCTION_3));
		Function latestFunction = latestFM.getFunctionAt(addr(latestProgram, THUNK_A_ENTRY));
		Function myFunction = myFM.getFunctionAt(addr(myProgram, THUNK_A_ENTRY));
		assertTrue(myExternalFunction.isExternal());
		assertTrue(!latestThunked.isExternal());
		assertTrue(!latestThunked.isThunk());
		assertTrue(latestFunction.isThunk());
		assertTrue(myFunction.isThunk());
		assertEquals(latestThunked, latestFunction.getThunkedFunction(false));
		assertEquals(myExternalFunction, myFunction.getThunkedFunction(false));

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
	public void testThunksToSameExternalFunctions() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);

					// Create a thunk to the external function.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, function.getEntryPoint());
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
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);

					// Create a thunk to the external function.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, function.getEntryPoint());
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
		FunctionManager latestFM = latestProgram.getFunctionManager();
		FunctionManager myFM = myProgram.getFunctionManager();

		Namespace latestExternalLibrary = (Namespace) getUniqueSymbol(latestProgram, "user32.dll",
			latestProgram.getGlobalNamespace()).getObject();
		assertNotNull(latestExternalLibrary);
		Symbol latestExternalApples =
			getUniqueSymbol(latestProgram, "apples", latestExternalLibrary);
		assertEquals(SymbolType.FUNCTION, latestExternalApples.getSymbolType());
		Function latestExternalFunction = (Function) latestExternalApples.getObject();

		Namespace myExternalLibrary = (Namespace) getUniqueSymbol(myProgram, "user32.dll",
			myProgram.getGlobalNamespace()).getObject();
		assertNotNull(myExternalLibrary);
		Symbol myExternalApples = getUniqueSymbol(myProgram, "apples", myExternalLibrary);
		assertEquals(SymbolType.FUNCTION, myExternalApples.getSymbolType());
		Function myExternalFunction = (Function) myExternalApples.getObject();

		Function latestFunction = latestFM.getFunctionAt(addr(latestProgram, THUNK_A_ENTRY));
		Function myFunction = myFM.getFunctionAt(addr(myProgram, THUNK_A_ENTRY));
		assertTrue(myExternalFunction.isExternal());
		assertTrue(latestExternalFunction.isExternal());
		assertTrue(latestFunction.isThunk());
		assertTrue(myFunction.isThunk());
		assertEquals(latestExternalFunction, latestFunction.getThunkedFunction(false));
		assertEquals(myExternalFunction, myFunction.getThunkedFunction(false));

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
	public void testThunksToExternalFunctionsSameNameDiffMemAddress() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);

					// Create a thunk to the external function.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, function.getEntryPoint());
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
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1130"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);

					// Create a thunk to the external function.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, function.getEntryPoint());
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
		FunctionManager latestFM = latestProgram.getFunctionManager();
		FunctionManager myFM = myProgram.getFunctionManager();

		Namespace latestExternalLibrary = (Namespace) getUniqueSymbol(latestProgram, "user32.dll",
			latestProgram.getGlobalNamespace()).getObject();
		assertNotNull(latestExternalLibrary);
		Symbol latestExternalApples =
			getUniqueSymbol(latestProgram, "apples", latestExternalLibrary);
		assertEquals(SymbolType.FUNCTION, latestExternalApples.getSymbolType());
		Function latestExternalFunction = (Function) latestExternalApples.getObject();

		Namespace myExternalLibrary = (Namespace) getUniqueSymbol(myProgram, "user32.dll",
			myProgram.getGlobalNamespace()).getObject();
		assertNotNull(myExternalLibrary);
		SymbolTable mySymTab = myProgram.getSymbolTable();
		Symbol myExternalApples = getUniqueSymbol(myProgram, "apples", myExternalLibrary);
		assertEquals(SymbolType.FUNCTION, myExternalApples.getSymbolType());
		Function myExternalFunction = (Function) myExternalApples.getObject();

		Function latestFunction = latestFM.getFunctionAt(addr(latestProgram, THUNK_A_ENTRY));
		Function myFunction = myFM.getFunctionAt(addr(myProgram, THUNK_A_ENTRY));
		assertTrue(myExternalFunction.isExternal());
		assertTrue(latestExternalFunction.isExternal());
		assertTrue(latestFunction.isThunk());
		assertTrue(myFunction.isThunk());
		assertEquals(latestExternalFunction, latestFunction.getThunkedFunction(false));
		assertEquals(myExternalFunction, myFunction.getThunkedFunction(false));

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
	public void testThunksToExternalFunctionsDiffNameSameMemAddress() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);

					// Create a thunk to the external function.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, function.getEntryPoint());
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
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "oranges",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);

					// Create a thunk to the external function.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, function.getEntryPoint());
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
		FunctionManager latestFM = latestProgram.getFunctionManager();
		FunctionManager myFM = myProgram.getFunctionManager();

		Namespace latestExternalLibrary = (Namespace) getUniqueSymbol(latestProgram, "user32.dll",
			latestProgram.getGlobalNamespace()).getObject();
		assertNotNull(latestExternalLibrary);
		Symbol latestExternalApples =
			getUniqueSymbol(latestProgram, "apples", latestExternalLibrary);
		assertEquals(SymbolType.FUNCTION, latestExternalApples.getSymbolType());
		Function latestExternalFunction = (Function) latestExternalApples.getObject();

		Namespace myExternalLibrary = (Namespace) getUniqueSymbol(myProgram, "user32.dll",
			myProgram.getGlobalNamespace()).getObject();
		assertNotNull(myExternalLibrary);
		Symbol myExternalApples = getUniqueSymbol(myProgram, "oranges", myExternalLibrary);
		assertEquals(SymbolType.FUNCTION, myExternalApples.getSymbolType());
		Function myExternalFunction = (Function) myExternalApples.getObject();

		Function latestFunction = latestFM.getFunctionAt(addr(latestProgram, THUNK_A_ENTRY));
		Function myFunction = myFM.getFunctionAt(addr(myProgram, THUNK_A_ENTRY));
		assertTrue(myExternalFunction.isExternal());
		assertTrue(latestExternalFunction.isExternal());
		assertTrue(latestFunction.isThunk());
		assertTrue(myFunction.isThunk());
		assertEquals(latestExternalFunction, latestFunction.getThunkedFunction(false));
		assertEquals(myExternalFunction, myFunction.getThunkedFunction(false));

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
	public void testThunksToExternalFunctionsDiffNameDiffMemAddress() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);

					// Create a thunk to the external function.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, function.getEntryPoint());
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
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "oranges",
							addr(program, "77db1130"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);

					// Create a thunk to the external function.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, function.getEntryPoint());
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
		FunctionManager latestFM = latestProgram.getFunctionManager();
		FunctionManager myFM = myProgram.getFunctionManager();

		Namespace latestExternalLibrary = (Namespace) getUniqueSymbol(latestProgram, "user32.dll",
			latestProgram.getGlobalNamespace()).getObject();
		assertNotNull(latestExternalLibrary);
		Symbol latestExternalApples =
			getUniqueSymbol(latestProgram, "apples", latestExternalLibrary);
		assertEquals(SymbolType.FUNCTION, latestExternalApples.getSymbolType());
		Function latestExternalFunction = (Function) latestExternalApples.getObject();

		Namespace myExternalLibrary = (Namespace) getUniqueSymbol(myProgram, "user32.dll",
			myProgram.getGlobalNamespace()).getObject();
		assertNotNull(myExternalLibrary);
		Symbol myExternalApples = getUniqueSymbol(myProgram, "oranges", myExternalLibrary);
		assertEquals(SymbolType.FUNCTION, myExternalApples.getSymbolType());
		Function myExternalFunction = (Function) myExternalApples.getObject();

		Function latestFunction = latestFM.getFunctionAt(addr(latestProgram, THUNK_A_ENTRY));
		Function myFunction = myFM.getFunctionAt(addr(myProgram, THUNK_A_ENTRY));
		assertTrue(myExternalFunction.isExternal());
		assertTrue(latestExternalFunction.isExternal());
		assertTrue(latestFunction.isThunk());
		assertTrue(myFunction.isThunk());
		assertEquals(latestExternalFunction, latestFunction.getThunkedFunction(false));
		assertEquals(myExternalFunction, myFunction.getThunkedFunction(false));

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

	//**************************
	// Helper methods.
	//**************************

	private Address addr(Program program, String address) {
		return program.getAddressFactory().getAddress(address);
	}
}
