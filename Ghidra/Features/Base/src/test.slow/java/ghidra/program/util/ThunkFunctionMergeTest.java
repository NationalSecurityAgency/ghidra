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

import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.program.database.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitorAdapter;

public class ThunkFunctionMergeTest extends AbstractGhidraHeadedIntegrationTest {

	private final static String THUNK_A_ENTRY = "0100199b";
	private final static String THUNK_A_END = "010019a1";
	private final static String THUNK_A_ALTERNATE_END = "010019c3";
	private final static String FUNCTION_1 = "0100248f";
	private final static String FUNCTION_3 = "01003bed";

	private MergeTestFacilitator mtf;

	private Program latestProgram;
	private Program myProgram;

	public ThunkFunctionMergeTest() {
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
	public void testSameThunkSoNoChange() throws Exception {

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

		AddressSetView as = latestProgram.getMemory();
		ProgramMergeManager programMerge =
			new ProgramMergeManager(latestProgram, myProgram, as, TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet diffAs = new AddressSet();
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());

		performMerge(as, programMerge);

		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

		FunctionManager functionManager = latestProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(latestProgram, THUNK_A_ENTRY));
		assertTrue(function.isThunk());
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(FUNCTION_1, thunkedFunction.getEntryPoint().toString());
	}

	@Test
	public void testDifferentThunkToAddress() throws Exception {

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

		AddressSetView as = latestProgram.getMemory();
		ProgramMergeManager programMerge =
			new ProgramMergeManager(latestProgram, myProgram, as, TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet diffAs =
			new AddressSet(addr(latestProgram, THUNK_A_ENTRY), addr(latestProgram, THUNK_A_ENTRY));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());

		performMerge(as, programMerge);

		assertEquals(new AddressSet(), programMerge.getFilteredDifferences()); // Shouldn't be any differences after merging.

		FunctionManager functionManager = latestProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(latestProgram, THUNK_A_ENTRY));
		assertTrue(function.isThunk());
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(FUNCTION_1, thunkedFunction.getEntryPoint().toString());
	}

	@Test
	public void testRemoveThunk() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with two params.
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
				// No thunk.
			}
		});

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSetView as = latestProgram.getMemory();
		ProgramMergeManager programMerge =
			new ProgramMergeManager(latestProgram, myProgram, as, TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(latestProgram, THUNK_A_ENTRY), addr(latestProgram, THUNK_A_ENTRY));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());

		performMerge(as, programMerge);

		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

		FunctionManager functionManager = latestProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(latestProgram, THUNK_A_ENTRY));
		assertNull(function);
	}

	@Test
	public void testAddThunk() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// No thunk function.
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

		AddressSetView as = latestProgram.getMemory();
		ProgramMergeManager programMerge =
			new ProgramMergeManager(latestProgram, myProgram, as, TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(latestProgram, THUNK_A_ENTRY), addr(latestProgram, THUNK_A_ENTRY));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());

		FunctionManager functionManager = latestProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(latestProgram, THUNK_A_ENTRY));
		assertNull(null);

		performMerge(as, programMerge);

		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

		functionManager = latestProgram.getFunctionManager();
		function = functionManager.getFunctionAt(addr(latestProgram, THUNK_A_ENTRY));
		assertTrue(function.isThunk());
	}

	@Test
	public void testChangeThunkBody() throws Exception {

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
				Function latestFunction =
					program.getFunctionManager().getFunctionAt(addr(program, THUNK_A_ENTRY));
				assertNotNull(latestFunction);
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
				Function myFunction =
					program.getFunctionManager().getFunctionAt(addr(program, THUNK_A_ENTRY));
				assertNotNull(myFunction);
			}
		});

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSetView as = latestProgram.getMemory();
		ProgramMergeManager programMerge =
			new ProgramMergeManager(latestProgram, myProgram, as, TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(latestProgram, THUNK_A_ENTRY), addr(latestProgram, THUNK_A_ENTRY));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());

		performMerge(as, programMerge);

		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

		FunctionManager functionManager = latestProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(latestProgram, THUNK_A_ENTRY));
		assertTrue(function.isThunk());
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(FUNCTION_1, thunkedFunction.getEntryPoint().toString());
		AddressSetView body = function.getBody();
		AddressSet expectedBody = new AddressSet(addr(latestProgram, THUNK_A_ENTRY),
			addr(latestProgram, THUNK_A_ALTERNATE_END));
		assertEquals(expectedBody, body);
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
				Function latestFunction =
					program.getFunctionManager().getFunctionAt(addr(program, THUNK_A_ENTRY));
				AddressSetView body = latestFunction.getBody();
				System.out.println("Latest function body = " + body.toString());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body = new AddressSet(addr(program, "01001984"),
						addr(program, THUNK_A_ALTERNATE_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, "01001984"), body, addr(program, FUNCTION_1));
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
				Function myFunction =
					program.getFunctionManager().getFunctionAt(addr(program, "01001984"));
				AddressSetView body = myFunction.getBody();
				System.out.println("My function body = " + body.toString());
			}
		});

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSetView as = latestProgram.getMemory();
		ProgramMergeManager programMerge =
			new ProgramMergeManager(latestProgram, myProgram, as, TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(latestProgram, "01001984"), addr(latestProgram, "01001984"));
		diffAs.addRange(addr(latestProgram, THUNK_A_ENTRY), addr(latestProgram, THUNK_A_ENTRY));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());

		performMerge(as, programMerge);

		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

		FunctionManager functionManager = latestProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(latestProgram, THUNK_A_ENTRY));
		assertNull(function);
		function = functionManager.getFunctionAt(addr(latestProgram, "01001984"));
		assertTrue(function.isThunk());
		AddressSet bodyAddressSet = new AddressSet(addr(latestProgram, "01001984"),
			addr(latestProgram, THUNK_A_ALTERNATE_END));
		assertEquals(bodyAddressSet, function.getBody());
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(FUNCTION_1, thunkedFunction.getEntryPoint().toString());
	}

	@Test
	public void testAddThunksWithBodyConflict() throws Exception {

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
				Function latestFunction =
					program.getFunctionManager().getFunctionAt(addr(program, THUNK_A_ENTRY));
				AddressSetView body = latestFunction.getBody();
				System.out.println("Latest function body = " + body.toString());
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
				Function myFunction =
					program.getFunctionManager().getFunctionAt(addr(program, THUNK_A_ENTRY));
				AddressSetView body = myFunction.getBody();
				System.out.println("My function body = " + body.toString());
			}
		});

		latestProgram = mtf.getLatestProgram();
		myProgram = mtf.getPrivateProgram();

		AddressSetView as = latestProgram.getMemory();
		ProgramMergeManager programMerge =
			new ProgramMergeManager(latestProgram, myProgram, as, TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(latestProgram, THUNK_A_ENTRY), addr(latestProgram, THUNK_A_ENTRY));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());

		performMerge(as, programMerge);

		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

		FunctionManager functionManager = latestProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(latestProgram, THUNK_A_ENTRY));
		assertTrue(function.isThunk());
		AddressSet bodyAddressSet = new AddressSet(addr(latestProgram, THUNK_A_ENTRY),
			addr(latestProgram, THUNK_A_ALTERNATE_END));
		assertEquals(bodyAddressSet, function.getBody());
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(FUNCTION_1, thunkedFunction.getEntryPoint().toString());
	}

	//**************************
	// Helper methods.
	//**************************

	private Address addr(Program program, String address) {
		return program.getAddressFactory().getAddress(address);
	}

	private void performMerge(AddressSetView as, ProgramMergeManager programMerge)
			throws Exception {
		boolean success = false;
		int latestId = latestProgram.startTransaction("Merge To Latest");
		try {
			programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
			success = true;
		}
		catch (Exception e) {
			throw e;
		}
		finally {
			latestProgram.endTransaction(latestId, success);
		}
	}
}
