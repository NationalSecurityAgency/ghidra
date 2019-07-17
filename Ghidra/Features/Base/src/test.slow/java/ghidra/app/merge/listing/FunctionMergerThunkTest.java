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

import javax.swing.JDialog;

import org.junit.Assert;
import org.junit.Test;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramDiff;
import ghidra.program.util.ProgramDiffFilter;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Test the multi-user merge of thunk functions.
 */
public class FunctionMergerThunkTest extends AbstractExternalMergerTest {

	private final static String OVERLAP_ENTRY = "01001994";
	private final static String THUNK_A_ENTRY = "0100199b";
	private final static String THUNK_A_END = "010019a1";
	private final static String THUNK_A_ALTERNATE_END = "010019c3";
//	private final static String NO_PARAMS_ENTRY = "01003a9e";
	private final static String NO_PARAMS_ENTRY = "0100194b";
//	private final static String ONE_PARAM_ENTRY = "01002950";
//	private final static String TWO_PARAMS_ENTRY = "01004a15";
	private final static String TWO_PARAMS_ENTRY = "01004c1d";

	/**
	 *
	 * @param arg0
	 */
	public FunctionMergerThunkTest() {
		super();
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
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, NO_PARAMS_ENTRY));
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
		waitForMergeCompletion();

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
	public void testAddDataVsThunkNoConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Create data.
					Address addr = addr(program, THUNK_A_ENTRY);
					Listing listing = program.getListing();
					Data data = listing.createData(addr, new ByteDataType());
					assertNotNull(data);
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
						addr(program, THUNK_A_ENTRY), body, addr(program, NO_PARAMS_ENTRY));
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
		JDialog dialog = waitForJDialog(null, "Function Merge Errors", 1000);
		assertNotNull(dialog);
		pressButtonByText(dialog, "OK");
		waitForMergeCompletion();

		Address entryAddress = addr(resultProgram, THUNK_A_ENTRY);
		AddressSet expectedDifferences = new AddressSet(entryAddress, entryAddress);
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
	public void testAddThunkToFunctionVsExternalPickLatest() throws Exception {

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
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		Function thunkFunction = getFunction(resultProgram, THUNK_A_ENTRY);
		assertNotNull(thunkFunction);
		assertTrue(thunkFunction.isThunk());
		Function thunkedFunction = thunkFunction.getThunkedFunction(false);
		assertNotNull(thunkedFunction);
		assertFalse(thunkedFunction.isExternal());
		assertEquals("FirstNamespace::FUN_0100194b", thunkedFunction.getName(true));
	}

	@Test
	public void testAddThunksToDifferentFunctionsChooseLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, NO_PARAMS_ENTRY));
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
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, TWO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());
	}

	@Test
	public void testAddThunksToDifferentFunctionsChooseMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, NO_PARAMS_ENTRY));
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
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, NO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());
	}

	@Test
	public void testAddDifferentBodyThunkPickLatest() throws Exception {

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
						addr(program, THUNK_A_ENTRY), body, addr(program, NO_PARAMS_ENTRY));
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
		chooseRadioButton(LATEST_BUTTON);
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
	public void testAddDifferentBodyThunkPickMy() throws Exception {

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
						addr(program, THUNK_A_ENTRY), body, addr(program, NO_PARAMS_ENTRY));
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
		chooseRadioButton(MY_BUTTON);
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
	public void testAddThunksWithBodyOverlapPickLatest() throws Exception {

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
					AddressSet body = new AddressSet(addr(program, OVERLAP_ENTRY),
						addr(program, THUNK_A_ALTERNATE_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, OVERLAP_ENTRY), body, addr(program, NO_PARAMS_ENTRY));
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
					program.getFunctionManager().getFunctionAt(addr(program, OVERLAP_ENTRY));
				assertNotNull(function);
			}
		});

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, OVERLAP_ENTRY), addr(resultProgram, OVERLAP_ENTRY));
		expectedDifferences.add(addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		chooseVariousOptions("01001994", new int[] { KEEP_LATEST });
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
	public void testAddThunksWithBodyOverlapPickMy() throws Exception {

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
					AddressSet body = new AddressSet(addr(program, OVERLAP_ENTRY),
						addr(program, THUNK_A_ALTERNATE_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, OVERLAP_ENTRY), body, addr(program, NO_PARAMS_ENTRY));
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
					program.getFunctionManager().getFunctionAt(addr(program, OVERLAP_ENTRY));
				assertNotNull(function);
			}
		});

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, OVERLAP_ENTRY), addr(resultProgram, OVERLAP_ENTRY));
		expectedDifferences.add(addr(resultProgram, THUNK_A_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);
		chooseVariousOptions("01001994", new int[] { KEEP_MY });
		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr(resultProgram, OVERLAP_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, NO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());
		AddressSet expectedBody = new AddressSet(addr(resultProgram, OVERLAP_ENTRY),
			addr(resultProgram, THUNK_A_ALTERNATE_END));
		assertEquals(expectedBody, function.getBody());
	}

	@Test
	public void testAddThunksToEquivalentExternals() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function externalFunction = createExternalFunction(program,
						new String[] { "user32.dll", "printf" }, addr(program, "77db1130"),
						new DWordDataType(), SourceType.USER_DEFINED);

					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd =
						new CreateThunkFunctionCmd(addr(program, THUNK_A_ENTRY), body,
							externalFunction.getExternalLocation().getExternalSpaceAddress());
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
		waitForMergeCompletion();

		Function thunkFunction = getFunction(resultProgram, THUNK_A_ENTRY);
		assertNotNull(thunkFunction);
		assertTrue(thunkFunction.isThunk());
		Function thunkedFunction = thunkFunction.getThunkedFunction(false);
		assertNotNull(thunkedFunction);
		assertTrue(thunkedFunction.isExternal());
		assertEquals("user32.dll::printf", thunkedFunction.getName(true));
		ExternalLocation externalLocation = thunkedFunction.getExternalLocation();
		assertEquals(addr(resultProgram, "77db1130"), externalLocation.getAddress());
	}

	@Test
	public void testAddThunksToExternalsDiffMemAddressesKeepLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function externalFunction = createExternalFunction(program,
						new String[] { "user32.dll", "printf" }, addr(program, "77db1020"),
						new DWordDataType(), SourceType.USER_DEFINED);

					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd =
						new CreateThunkFunctionCmd(addr(program, THUNK_A_ENTRY), body,
							externalFunction.getExternalLocation().getExternalSpaceAddress());
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
						new String[] { "user32.dll", "printf" }, addr(program, "77db1130"),
						new DWordDataType(), SourceType.USER_DEFINED);

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
		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		Function thunkFunction = getFunction(resultProgram, THUNK_A_ENTRY);
		assertNotNull(thunkFunction);
		assertTrue(thunkFunction.isThunk());
		Function thunkedFunction = thunkFunction.getThunkedFunction(false);
		assertNotNull(thunkedFunction);
		assertTrue(thunkedFunction.isExternal());
		assertEquals("user32.dll::printf", thunkedFunction.getName(true));
		ExternalLocation externalLocation = thunkedFunction.getExternalLocation();
		assertEquals(addr(resultProgram, "77db1020"), externalLocation.getAddress());
	}

	@Test
	public void testAddThunksToExternalsDiffMemAddressesKeepMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function externalFunction = createExternalFunction(program,
						new String[] { "user32.dll", "printf" }, addr(program, "77db1020"),
						new DWordDataType(), SourceType.USER_DEFINED);

					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd =
						new CreateThunkFunctionCmd(addr(program, THUNK_A_ENTRY), body,
							externalFunction.getExternalLocation().getExternalSpaceAddress());
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
						new String[] { "user32.dll", "printf" }, addr(program, "77db1130"),
						new DWordDataType(), SourceType.USER_DEFINED);

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
		chooseButtonAndApply("Resolve External Add Conflict", MY_BUTTON);
		waitForMergeCompletion();

		Function thunkFunction = getFunction(resultProgram, THUNK_A_ENTRY);
		assertNotNull(thunkFunction);
		assertTrue(thunkFunction.isThunk());
		Function thunkedFunction = thunkFunction.getThunkedFunction(false);
		assertNotNull(thunkedFunction);
		assertTrue(thunkedFunction.isExternal());
		assertEquals("user32.dll::printf", thunkedFunction.getName(true));
		ExternalLocation externalLocation = thunkedFunction.getExternalLocation();
		assertEquals(addr(resultProgram, "77db1130"), externalLocation.getAddress());
	}

	@Test
	public void testAddThunksToExternalsDiffMemAddressesKeepBoth() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function externalFunction = createExternalFunction(program,
						new String[] { "user32.dll", "printf" }, addr(program, "77db1020"),
						new DWordDataType(), SourceType.USER_DEFINED);

					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd =
						new CreateThunkFunctionCmd(addr(program, THUNK_A_ENTRY), body,
							externalFunction.getExternalLocation().getExternalSpaceAddress());
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
						new String[] { "user32.dll", "printf" }, addr(program, "77db1130"),
						new DWordDataType(), SourceType.USER_DEFINED);

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
		chooseButtonAndApply("Resolve External Add Conflict", KEEP_BOTH_BUTTON);
		waitForMergeCompletion();

		Function thunkFunction = getFunction(resultProgram, THUNK_A_ENTRY);
		assertNotNull(thunkFunction);
		assertTrue(thunkFunction.isThunk());
		Function thunkedFunction = thunkFunction.getThunkedFunction(false);
		assertNotNull(thunkedFunction);
		assertTrue(thunkedFunction.isExternal());
		assertEquals("user32.dll::printf", thunkedFunction.getName(true));
		ExternalLocation externalLocation = thunkedFunction.getExternalLocation();
		assertEquals(addr(resultProgram, "77db1020"), externalLocation.getAddress());

		List<ExternalLocation> externalLocations =
			resultProgram.getExternalManager().getExternalLocations("user32.dll", "printf");
		assertEquals(2, externalLocations.size());
		Address address1 = externalLocations.get(0).getAddress();
		Address address2 = externalLocations.get(1).getAddress();
		assertTrue("Expected one location to be ", areOneOfEach(address1, address2,
			addr(resultProgram, "77db1020"), addr(resultProgram, "77db1130")));

	}

	private <T> boolean areOneOfEach(T t1, T t2, T v1, T v2) {

		if (t1.equals(v1) && t2.equals(v2)) {
			return true;
		}

		if (t1.equals(v2) && t2.equals(v1)) {
			return true;
		}

		return false;
	}

	@Test
	public void testAddThunksToExternalsDiffMemAddressesMergeBothKeepLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function externalFunction = createExternalFunction(program,
						new String[] { "user32.dll", "printf" }, addr(program, "77db1020"),
						new DWordDataType(), SourceType.USER_DEFINED);

					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd =
						new CreateThunkFunctionCmd(addr(program, THUNK_A_ENTRY), body,
							externalFunction.getExternalLocation().getExternalSpaceAddress());
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
						new String[] { "user32.dll", "printf" }, addr(program, "77db1130"),
						new DWordDataType(), SourceType.USER_DEFINED);

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
		chooseButtonAndApply("Resolve External Add Conflict", ListingMergeConstants.LATEST_BUTTON_NAME);
		waitForMergeCompletion();

		Function thunkFunction = getFunction(resultProgram, THUNK_A_ENTRY);
		assertNotNull(thunkFunction);
		assertTrue(thunkFunction.isThunk());
		Function thunkedFunction = thunkFunction.getThunkedFunction(false);
		assertNotNull(thunkedFunction);
		assertTrue(thunkedFunction.isExternal());
		assertEquals("user32.dll::printf", thunkedFunction.getName(true));
		ExternalLocation externalLocation = thunkedFunction.getExternalLocation();
		assertEquals(addr(resultProgram, "77db1020"), externalLocation.getAddress());
	}

	@Test
	public void testAddThunksToExternalsDiffMemAddressesMergeBothKeepMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function externalFunction = createExternalFunction(program,
						new String[] { "user32.dll", "printf" }, addr(program, "77db1020"),
						new DWordDataType(), SourceType.USER_DEFINED);

					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd =
						new CreateThunkFunctionCmd(addr(program, THUNK_A_ENTRY), body,
							externalFunction.getExternalLocation().getExternalSpaceAddress());
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
						new String[] { "user32.dll", "printf" }, addr(program, "77db1130"),
						new DWordDataType(), SourceType.USER_DEFINED);

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
		chooseButtonAndApply("Resolve External Add Conflict", ListingMergeConstants.CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		Function thunkFunction = getFunction(resultProgram, THUNK_A_ENTRY);
		assertNotNull(thunkFunction);
		assertTrue(thunkFunction.isThunk());
		Function thunkedFunction = thunkFunction.getThunkedFunction(false);
		assertNotNull(thunkedFunction);
		assertTrue(thunkedFunction.isExternal());
		assertEquals("user32.dll::printf", thunkedFunction.getName(true));
		ExternalLocation externalLocation = thunkedFunction.getExternalLocation();
		assertEquals(addr(resultProgram, "77db1130"), externalLocation.getAddress());
	}

	@Test
	public void testAddThunksToDifferentExternalsPickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function externalFunction = createExternalFunction(program,
						new String[] { "user32.dll", "printf" }, addr(program, "77db1130"),
						new DWordDataType(), SourceType.USER_DEFINED);

					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd =
						new CreateThunkFunctionCmd(addr(program, THUNK_A_ENTRY), body,
							externalFunction.getExternalLocation().getExternalSpaceAddress());
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
						new String[] { "user32.dll", "scanf" }, new DWordDataType());

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
		chooseRadioButton("Resolve External Add Conflict", KEEP_BOTH_BUTTON); // keep both externals causes thunk conflict
		chooseRadioButton("Resolve Thunk Function Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		Function thunkFunction = getFunction(resultProgram, THUNK_A_ENTRY);
		assertNotNull(thunkFunction);
		assertTrue(thunkFunction.isThunk());
		Function thunkedFunction = thunkFunction.getThunkedFunction(false);
		assertNotNull(thunkedFunction);
		assertTrue(thunkedFunction.isExternal());
		assertEquals("user32.dll::printf", thunkedFunction.getName(true));
		ExternalLocation externalLocation = thunkedFunction.getExternalLocation();
		assertEquals(addr(resultProgram, "77db1130"), externalLocation.getAddress());
	}

	@Test
	public void testAddThunksToDifferentExternalsPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function externalFunction = createExternalFunction(program,
						new String[] { "user32.dll", "printf" }, addr(program, "77db1130"),
						new DWordDataType(), SourceType.USER_DEFINED);

					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd =
						new CreateThunkFunctionCmd(addr(program, THUNK_A_ENTRY), body,
							externalFunction.getExternalLocation().getExternalSpaceAddress());
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
						new String[] { "user32.dll", "scanf" }, new DWordDataType());

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
		chooseRadioButton("Resolve External Add Conflict", KEEP_BOTH_BUTTON); // keep both externals causes thunk conflict
		chooseRadioButton("Resolve Thunk Function Conflict", MY_BUTTON);
		waitForMergeCompletion();

		Function thunkFunction = getFunction(resultProgram, THUNK_A_ENTRY);
		assertNotNull(thunkFunction);
		assertTrue(thunkFunction.isThunk());
		Function thunkedFunction = thunkFunction.getThunkedFunction(false);
		assertNotNull(thunkedFunction);
		assertTrue(thunkedFunction.isExternal());
		assertEquals("user32.dll::scanf", thunkedFunction.getName(true));
		ExternalLocation externalLocation = thunkedFunction.getExternalLocation();
		assertNull(externalLocation.getAddress());
	}

	@Test
	public void testAddFunctionVsThunkPickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
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

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
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
		chooseRadioButton(LATEST_BUTTON);
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
	public void testAddFunctionVsThunkPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
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

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
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
		chooseRadioButton(MY_BUTTON);
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
	public void testAddDifferentThunkNamePickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				FunctionManager functionManager = program.getFunctionManager();
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
					Function function = functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					function.setName("LatestThunk", SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function = functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
				assertNotNull(function);
				assertEquals("LatestThunk", function.getName());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				FunctionManager functionManager = program.getFunctionManager();
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, NO_PARAMS_ENTRY));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Private program.");
					}
					Function function = functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					function.setName("MyThunk", SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function = functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
				assertNotNull(function);
				assertEquals("MyThunk", function.getName());
			}
		});

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences = new AddressSet(addr(resultProgram, THUNK_A_ENTRY));
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
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, NO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());
		AddressSet expectedBody =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_END));
		assertEquals(expectedBody, function.getBody());
		assertEquals("LatestThunk", function.getName());
	}

	@Test
	public void testAddDifferentThunkNamePickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				FunctionManager functionManager = program.getFunctionManager();
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
					Function function = functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					function.setName("LatestThunk", SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function = functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
				assertNotNull(function);
				assertEquals("LatestThunk", function.getName());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				FunctionManager functionManager = program.getFunctionManager();
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet body =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), body, addr(program, NO_PARAMS_ENTRY));
					boolean created = cmd.applyTo(program);
					if (!created) {
						Assert.fail("Couldn't create thunk in Private program.");
					}
					Function function = functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
					function.setName("MyThunk", SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function = functionManager.getFunctionAt(addr(program, THUNK_A_ENTRY));
				assertNotNull(function);
				assertEquals("MyThunk", function.getName());
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
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, NO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());
		AddressSet expectedBody =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_END));
		assertEquals(expectedBody, function.getBody());
		assertEquals("MyThunk", function.getName());
	}

}
