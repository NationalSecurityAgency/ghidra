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

import org.junit.Assert;
import org.junit.Test;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.program.database.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramDiff;
import ghidra.program.util.ProgramDiffFilter;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Test the multi-user merge of thunk functions.
 */
public class FunctionMergerThunk2Test extends AbstractExternalMergerTest {

	private final static String OVERLAP_ENTRY = "01001994";
	private final static String THUNK_A_ENTRY = "0100199b";
	private final static String THUNK_A_END = "010019a1";
	private final static String THUNK_A_ALTERNATE_END = "010019c3";
//	private final static String NO_PARAMS_ENTRY = "01003a9e";
	private final static String NO_PARAMS_ENTRY = "0100194b";
//	private final static String ONE_PARAM_ENTRY = "01002950";
	private final static String ONE_PARAM_ENTRY = "01002b44";
//	private final static String TWO_PARAMS_ENTRY = "01004a15";
	private final static String TWO_PARAMS_ENTRY = "01004c1d";

	/**
	 *
	 * @param arg0
	 */
	public FunctionMergerThunk2Test() {
		super();
	}

	@Test
	public void testAddThunkToFunctionVsExternalPickMy() throws Exception {

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
						addr(program, THUNK_A_ENTRY), body, addr(program, NO_PARAMS_ENTRY));
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
					Function externalFunction = createExternalFunction(program,
						new String[] { "user32.dll", "printf" }, new DWordDataType());

					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd =
						new CreateThunkFunctionCmd(addr(program, THUNK_A_ENTRY), body,
							externalFunction.getExternalLocation().getExternalSpaceAddress());
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

		executeMerge(ASK_USER);
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		Function thunkFunction = getFunction(resultProgram, THUNK_A_ENTRY);
		assertNotNull(thunkFunction);
		assertTrue(thunkFunction.isThunk());
		Function thunkedFunction = thunkFunction.getThunkedFunction(false);
		assertNotNull(thunkedFunction);
		assertTrue(thunkedFunction.isExternal());
		assertEquals("user32.dll::printf", thunkedFunction.getName(true));
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
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, TWO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());
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
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, TWO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());
	}

	@Test
	public void testChangeThunkPointedToDifferentlyInEachPickLatest() throws Exception {

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
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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
						functionManager.getFunctionAt(addr(program, ONE_PARAM_ENTRY));
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
						functionManager.getFunctionAt(addr(program, NO_PARAMS_ENTRY));
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Thunk Function Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, ONE_PARAM_ENTRY), thunkedFunction.getEntryPoint());
		AddressSet expectedBody =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_END));
		assertEquals(expectedBody, function.getBody());
	}

	@Test
	public void testChangeThunkPointedToDifferentlyInEachPickMy() throws Exception {

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
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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
						functionManager.getFunctionAt(addr(program, ONE_PARAM_ENTRY));
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
						functionManager.getFunctionAt(addr(program, NO_PARAMS_ENTRY));
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Thunk Function Conflict", MY_BUTTON);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, NO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());
		AddressSet expectedBody =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_END));
		assertEquals(expectedBody, function.getBody());
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
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, TWO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());
		AddressSet expectedBody = new AddressSet(addr(resultProgram, THUNK_A_ENTRY),
			addr(resultProgram, THUNK_A_ALTERNATE_END));
		assertEquals(expectedBody, function.getBody());
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
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, TWO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());
		AddressSet expectedBody = new AddressSet(addr(resultProgram, THUNK_A_ENTRY),
			addr(resultProgram, THUNK_A_ALTERNATE_END));
		assertEquals(expectedBody, function.getBody());
	}

	@Test
	public void testAddThunkVsNonThunkPickLatest() throws Exception {

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
						addr(program, "0100199b"), body, addr(program, NO_PARAMS_ENTRY));
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
					// Create a simple function with no params.
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Thunk Function Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, NO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());
		AddressSet expectedBody = new AddressSet(addr(resultProgram, THUNK_A_ENTRY),
			addr(resultProgram, THUNK_A_ALTERNATE_END));
		assertEquals(expectedBody, function.getBody());
	}

	@Test
	public void testAddThunkVsNonThunkPickMy() throws Exception {

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
						addr(program, "0100199b"), body, addr(program, NO_PARAMS_ENTRY));
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Thunk Function Conflict", MY_BUTTON);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertNull(thunkedFunction);
		assertFalse(function.isThunk());
		AddressSet expectedBody = new AddressSet(addr(resultProgram, THUNK_A_ENTRY),
			addr(resultProgram, THUNK_A_ALTERNATE_END));
		assertEquals(expectedBody, function.getBody());
	}

	@Test
	public void testAddThunkWhereDefaultThunkIsToSameFunction() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Setup Original Program");
				boolean commit = false;
				try {
					// Create a thunk function to TWO_PARAMS_ENTRY.
					removeFunction(program, "01001ae3");
					AddressSet body =
						new AddressSet(addr(program, "01001e22"), addr(program, "01001e30"));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, "01001e22"), body, addr(program, TWO_PARAMS_ENTRY));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Original program.");
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
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Create a thunk to NO_PARAMS_ENTRY.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, NO_PARAMS_ENTRY));
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
					// Create a thunk to TWO_PARAMS_ENTRY.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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
		});

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Thunk Function Conflict", MY_BUTTON);
		waitForMergeCompletion();

		// There should be two thunks to TWO_PARAMS_ENTRY and none to NO_PARAMS_ENTRY.
		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function originalFunction = functionManager.getFunctionAt(addr(resultProgram, "01001e22"));
		Function mergedFunction = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(originalFunction);
		assertNotNull(mergedFunction);
		assertTrue(originalFunction.isThunk());
		assertTrue(mergedFunction.isThunk());
		Function originalThunkedFunction = originalFunction.getThunkedFunction(false);
		assertNotNull(originalThunkedFunction);
		Function mergedThunkedFunction = mergedFunction.getThunkedFunction(false);
		assertNotNull(mergedThunkedFunction);
		AddressSet expectedOriginalBody =
			new AddressSet(addr(resultProgram, "01001e22"), addr(resultProgram, "01001e30"));
		AddressSet expectedMergedBody =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_END));
		assertEquals(expectedOriginalBody, originalFunction.getBody());
		assertEquals(expectedMergedBody, mergedFunction.getBody());
	}

	@Test
	public void testChangeThunkVersusRemovePickLatest() throws Exception {

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
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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

					AddressSet body = new AddressSet(addr(program, OVERLAP_ENTRY),
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
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					FunctionManager functionManager = program.getFunctionManager();
					Function thunkFunction =
						functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					assertNotNull(thunkFunction);

					functionManager.removeFunction(addr(program, THUNK_A_ENTRY));
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Remove Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, TWO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());
		AddressSet expectedBody = new AddressSet(addr(resultProgram, OVERLAP_ENTRY),
			addr(resultProgram, THUNK_A_ALTERNATE_END));
		assertEquals(expectedBody, function.getBody());
	}

	@Test
	public void testChangeThunkVersusRemovePickMy() throws Exception {

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
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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

					AddressSet body = new AddressSet(addr(program, OVERLAP_ENTRY),
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
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					FunctionManager functionManager = program.getFunctionManager();
					Function thunkFunction =
						functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					assertNotNull(thunkFunction);

					functionManager.removeFunction(addr(program, THUNK_A_ENTRY));
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Remove Conflict", MY_BUTTON);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNull(function);
	}

	@Test
	public void testRemoveThunkVersusChangePickLatest() throws Exception {

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
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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

					functionManager.removeFunction(addr(program, THUNK_A_ENTRY));
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
					FunctionManager functionManager = program.getFunctionManager();
					Function thunkFunction =
						functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					assertNotNull(thunkFunction);

					AddressSet body = new AddressSet(addr(program, OVERLAP_ENTRY),
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Remove Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNull(function);
	}

	@Test
	public void testRemoveThunkVersusChangePickMy() throws Exception {

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
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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

					functionManager.removeFunction(addr(program, THUNK_A_ENTRY));
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
					FunctionManager functionManager = program.getFunctionManager();
					Function thunkFunction =
						functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					assertNotNull(thunkFunction);

					AddressSet body = new AddressSet(addr(program, OVERLAP_ENTRY),
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Remove Conflict", MY_BUTTON);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, TWO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());
		AddressSet expectedBody = new AddressSet(addr(resultProgram, OVERLAP_ENTRY),
			addr(resultProgram, THUNK_A_ALTERNATE_END));
		assertEquals(expectedBody, function.getBody());
	}

	@Test
	public void testCreateThunkVersusRemoveThunkedFunction() throws Exception {

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
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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
					FunctionManager functionManager = program.getFunctionManager();
					Function thunkFunction =
						functionManager.getFunctionAt(addr(program, TWO_PARAMS_ENTRY));
					assertNotNull(thunkFunction);

					functionManager.removeFunction(addr(program, TWO_PARAMS_ENTRY));
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		expectedDifferences.add(addr(resultProgram, TWO_PARAMS_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNull(function);
		function = functionManager.getFunctionAt(addr(resultProgram, TWO_PARAMS_ENTRY));
		assertNull(function);
	}

	@Test
	public void testRemoveThunkedFunctionVersusCreateThunk() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					FunctionManager functionManager = program.getFunctionManager();
					Function thunkedFunction =
						functionManager.getFunctionAt(addr(program, TWO_PARAMS_ENTRY));
					assertNotNull(thunkedFunction);

					functionManager.removeFunction(addr(program, TWO_PARAMS_ENTRY));
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
					// Create a thunk to the function with two params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in MY program.");
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		expectedDifferences.add(addr(resultProgram, TWO_PARAMS_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		waitForReadTextDialog("Function Merge Errors", "Can't replace thunk", 3000);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNull(function);
		function = functionManager.getFunctionAt(addr(resultProgram, TWO_PARAMS_ENTRY));
		assertNull(function);
	}

	@Test
	public void testChangeThunkNamesDifferentlyPickLatest() throws Exception {

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
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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

					thunkFunction.setName("LatestThunk", SourceType.USER_DEFINED);
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
					FunctionManager functionManager = program.getFunctionManager();
					Function thunkFunction =
						functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					assertNotNull(thunkFunction);

					thunkFunction.setName("MyThunk", SourceType.USER_DEFINED);
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Conflict",
			new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		assertEquals("LatestThunk", function.getName());
		AddressSet expectedBody =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_END));
		assertEquals(expectedBody, function.getBody());
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals("FUN_" + TWO_PARAMS_ENTRY, thunkedFunction.getName());
	}

	@Test
	public void testChangeThunkNamesDifferentlyPickMy() throws Exception {

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
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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

					thunkFunction.setName("LatestThunk", SourceType.USER_DEFINED);
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
					FunctionManager functionManager = program.getFunctionManager();
					Function thunkFunction =
						functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					assertNotNull(thunkFunction);

					thunkFunction.setName("MyThunk", SourceType.USER_DEFINED);
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Conflict",
			new int[] { INFO_ROW, KEEP_MY });
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		assertEquals("MyThunk", function.getName());
		AddressSet expectedBody =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_END));
		assertEquals(expectedBody, function.getBody());
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals("FUN_" + TWO_PARAMS_ENTRY, thunkedFunction.getName());
	}

	@Test
	public void testChangeThunkedNameWhenThunkIsDefaultPickMy() throws Exception {

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
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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
					Function thunkedFunction =
						functionManager.getFunctionAt(addr(program, TWO_PARAMS_ENTRY));
					assertNotNull(thunkedFunction);

					thunkedFunction.setName("LatestThunk", SourceType.USER_DEFINED);
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
					FunctionManager functionManager = program.getFunctionManager();
					Function thunkFunction =
						functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					assertNotNull(thunkFunction);
					Function thunkedFunction =
						functionManager.getFunctionAt(addr(program, TWO_PARAMS_ENTRY));
					assertNotNull(thunkedFunction);

					thunkedFunction.setName("MyThunk", SourceType.USER_DEFINED);
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences = new AddressSet(addr(resultProgram, TWO_PARAMS_ENTRY),
			addr(resultProgram, TWO_PARAMS_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Conflict",
			new int[] { INFO_ROW, KEEP_MY });
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		assertEquals("MyThunk", function.getName());
		AddressSet expectedBody =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_END));
		assertEquals(expectedBody, function.getBody());
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals("MyThunk", thunkedFunction.getName());
	}

	@Test
	public void testChangeThunkedNameWhenThunkIsNotDefaultPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Setup Original Program");
				boolean commit = false;
				try {
					FunctionManager functionManager = program.getFunctionManager();
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}
					Function thunkFunction =
						functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					assertNotNull(thunkFunction);
					thunkFunction.setName("OriginalThunk", SourceType.USER_DEFINED);
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
					Function thunkedFunction =
						functionManager.getFunctionAt(addr(program, TWO_PARAMS_ENTRY));
					assertNotNull(thunkedFunction);

					thunkedFunction.setName("LatestThunked", SourceType.USER_DEFINED);
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
					FunctionManager functionManager = program.getFunctionManager();
					Function thunkedFunction =
						functionManager.getFunctionAt(addr(program, TWO_PARAMS_ENTRY));
					assertNotNull(thunkedFunction);

					thunkedFunction.setName("MyThunked", SourceType.USER_DEFINED);
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences = new AddressSet(addr(resultProgram, TWO_PARAMS_ENTRY),
			addr(resultProgram, TWO_PARAMS_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Conflict",
			new int[] { INFO_ROW, KEEP_MY });
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		assertEquals("OriginalThunk", function.getName());
		AddressSet expectedBody =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_END));
		assertEquals(expectedBody, function.getBody());
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals("MyThunked", thunkedFunction.getName());
	}

	@Test
	public void testSetThunkNameInJustMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				// Add the thunk to the Original program.
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, TWO_PARAMS_ENTRY));
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
				// Do nothing. Only wanted thunk added to My.
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					FunctionManager functionManager = program.getFunctionManager();
					Function function = functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					assertNotNull(function);
					assertTrue(function.isThunk());
					Function thunkedFunction = function.getThunkedFunction(true);
					assertNotNull(thunkedFunction);
					assertEquals(addr(program, TWO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());

					function.setName("CoolStuff", SourceType.USER_DEFINED);
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

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, TWO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());
		assertEquals("CoolStuff", function.getName());
	}

}
