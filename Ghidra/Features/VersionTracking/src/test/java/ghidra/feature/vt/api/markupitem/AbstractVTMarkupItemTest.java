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
package ghidra.feature.vt.api.markupitem;

import static ghidra.feature.vt.db.VTTestUtils.*;
import static ghidra.feature.vt.gui.util.VTOptionDefines.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Before;

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.task.*;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.test.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public abstract class AbstractVTMarkupItemTest extends AbstractGhidraHeadedIntegrationTest {

	public static final String TEST_ADDRESS_SOURCE = "Test";
	private TestEnv env;
	protected ProgramBuilder sourceBuilder;
	protected ProgramBuilder destinationBuilder;
	protected ProgramDB sourceProgram;
	protected ProgramDB destinationProgram;

	// make sure all random names are unique
	private int nameCounter = 0;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		setErrorGUIEnabled(false);

		sourceBuilder = new ClassicSampleX86ProgramBuilder("notepadSrc", true, this);
		sourceProgram = sourceBuilder.getProgram();

		destinationBuilder = new ClassicSampleX86ProgramBuilder("notepadDest", true, this);
		destinationProgram = destinationBuilder.getProgram();

		setupPrograms(sourceBuilder, destinationBuilder);
	}

	private void setupPrograms(ProgramBuilder sourceBuilder, ProgramBuilder destinationBuilder)
			throws Exception {

		createFunction_01003f9e(sourceBuilder);
		createFunction_01003f9e(destinationBuilder);

		createData(sourceBuilder);
		createData(destinationBuilder);
	}

	private void createFunction_01003f9e(ProgramBuilder builder) throws Exception {
		String entry = "0x01003f9e";
		builder.setBytes(entry,
			"55 8b ec 51 51 53 56 33 db 57 8d 45 fc 53 bf a0 90 00 01 50 57 e8 90 26 00 00 " +
				"85 c0 0f 84 9c 00 00 00 8d 45 f8 50 53 53 6a 01 53 ff 75 fc e8 71 26 00 00 ff " +
				"75 f8 6a 40 ff 15 dc 10 00 01 8b f0 3b f3 74 1e 8d 45 f8 50 ff 75 f8 56 6a 01 " +
				"53 ff 75 fc e8 4d 26 00 00 85 c0 75 11 56 ff 15 c0 10 00 01 ff 75 fc e8 34 26 " +
				"00 00 eb 52 80 0d f1 8b 00 01 04 68 e0 8b 00 01 e8 bd f0 ff ff 80 25 f1 8b 00 " +
				"01 fb 53 53 57 ff 36 ff 15 68 10 00 01 56 8b f8 ff 15 c0 10 00 01 ff 75 fc e8 " +
				"fe 25 00 00 3b fb 75 1f 6a 30 ff 35 50 80 00 01 ff 35 8c 80 00 01 ff 35 d0 87 " +
				"00 01 ff 15 04 12 00 01 83 c8 ff eb 02 8b c7 5f 5e 5b c9 c3");
		builder.disassemble(
			new AddressSet(sourceProgram, builder.addr(entry), builder.addr("01004067")));
		builder.createFunction(entry);
	}

	private void createData(ProgramBuilder builder) throws Exception {
		// "LoadCursorW", 00
		builder.setBytes("0x010074e6", "4c 6f 61 64 43 75 72 73 6f 72 57 00");
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
		if (sourceProgram != null) {
			sourceProgram.release(this);
		}
		if (destinationProgram != null) {
			destinationProgram.release(this);
		}
	}

	/**
	 * A class that lets subclasses provide data and the algorithms to test the application of
	 * that data.
	 */
	protected abstract class TestDataProviderAndValidator {

		protected abstract Address getSourceMatchAddress();

		protected abstract Address getDestinationMatchAddress();

		protected abstract VTMarkupItem searchForMarkupItem(VTMatch match) throws Exception;

		protected abstract VTMarkupItemApplyActionType getApplyAction();

		protected abstract void assertApplied();

		protected abstract void assertUnapplied();

		protected abstract Address getDestinationApplyAddress();

		protected static final String VERSION_TRACKING_OPTIONS_NAME = "Version Tracking";

		/**
		 * Override this method if you want the options used by the validator to differ from the
		 * default version tracking Apply Markup Options.
		 * @return the Apply Markup Options for the validator to use.
		 */
		protected ToolOptions getOptions() {
			ToolOptions applyOptions = new ToolOptions(VERSION_TRACKING_OPTIONS_NAME);

			applyOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.REPLACE_ALWAYS);
			applyOptions.setEnum(LABELS, LabelChoices.ADD);

			applyOptions.setEnum(FUNCTION_SIGNATURE,
				FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
			applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
			applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
			applyOptions.setEnum(NO_RETURN, ReplaceChoices.REPLACE);
			applyOptions.setEnum(FUNCTION_RETURN_TYPE,
				ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
			applyOptions.setEnum(PARAMETER_DATA_TYPES,
				ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
			applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.PRIORITY_REPLACE);
			applyOptions.setEnum(HIGHEST_NAME_PRIORITY,
				HighestSourcePriorityChoices.USER_PRIORITY_HIGHEST);
			applyOptions.setBoolean(PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY,
				DEFAULT_OPTION_FOR_PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY);
//			applyOptions.putBoolean(PARAMETER_NAMES_ONLY_REPLACE_DEFAULTS, false);
//			applyOptions.putBoolean(PARAMETER_NAMES_DO_NOT_REPLACE_WITH_DEFAULTS, false);
			applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);

			applyOptions.setEnum(PLATE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
			applyOptions.setEnum(PRE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
			applyOptions.setEnum(END_OF_LINE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
			applyOptions.setEnum(REPEATABLE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
			applyOptions.setEnum(POST_COMMENT, CommentChoices.APPEND_TO_EXISTING);

			applyOptions.setEnum(DATA_MATCH_DATA_TYPE,
				ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY);
			return applyOptions;
		}
	}

	protected void doTestFindAndApplyMarkupItem(TestDataProviderAndValidator validator)
			throws Exception {

		VTSessionDB session = createNewSession();
		VTMatch match = createMatchSetWithOneMatch(session, validator.getSourceMatchAddress(),
			validator.getDestinationMatchAddress());
		VTMarkupItem markupItem = validator.searchForMarkupItem(match);

		//
		// verify we cannot unapply before we have applied
		//
		List<VTMarkupItem> markupItems = new ArrayList<>();
		Address destinationApplyAddress = validator.getDestinationApplyAddress();
		markupItem.setDefaultDestinationAddress(destinationApplyAddress, TEST_ADDRESS_SOURCE);
		markupItems.add(markupItem);

		//
		// verify we can apply
		//
		VTMarkupItemApplyActionType applyAction = validator.getApplyAction();
		if (applyAction != null) {
			VtTask task = new ApplyMarkupItemTask(session, markupItems, validator.getOptions());
			runTask(session, task);
			assertEquals("The markup item status was not correctly set",
				applyAction.getApplyStatus(), markupItem.getStatus());
			validator.assertApplied();
			//
			// Verify we can unapply
			//
			task = new UnapplyMarkupItemTask(session, null, markupItems);
			runTask(session, task);
			validator.assertUnapplied();
		}
		else {// ignore it
			VtTask task = new TagMarkupItemTask(session, markupItems,
				VTMarkupItemConsideredStatus.IGNORE_DONT_CARE);
			runTask(session, task);
			assertEquals("The markup item status was not correctly set",
				VTMarkupItemStatus.DONT_CARE, markupItem.getStatus());
			//
			// Verify we can untag
			//
			task = new ClearMarkupItemConsideredStatusTask(markupItems);
			runTask(session, task);
			validator.assertUnapplied();
		}
	}

	protected void doTestFindAndApplyMarkupItem_NoEffect(TestDataProviderAndValidator validator)
			throws Exception {

		VTSessionDB session = createNewSession();
		VTMatch match = createMatchSetWithOneMatch(session, validator.getSourceMatchAddress(),
			validator.getDestinationMatchAddress());
		VTMarkupItem markupItem = validator.searchForMarkupItem(match);

		//
		// verify we cannot unapply before we have applied
		//
		List<VTMarkupItem> markupItems = new ArrayList<>();
		Address destinationApplyAddress = validator.getDestinationApplyAddress();
		markupItem.setDefaultDestinationAddress(destinationApplyAddress, TEST_ADDRESS_SOURCE);
		markupItems.add(markupItem);

		VtTask task = new UnapplyMarkupItemTask(session, null, markupItems);
		runTask(session, task);

		//
		// verify we can apply
		//
		VTMarkupItemApplyActionType applyAction = validator.getApplyAction();
		if (applyAction != null) {
			task = new ApplyMarkupItemTask(session, markupItems, validator.getOptions());
			runTask(session, task);
			assertEquals("The markup item was applied when it should not have been.",
				VTMarkupItemStatus.UNAPPLIED, markupItem.getStatus());
		}

	}

	protected boolean doCheckForSameMarkupItem(TestDataProviderAndValidator validator)
			throws Exception {

		VTSessionDB session = createNewSession();
		VTMatch match = createMatchSetWithOneMatch(session, validator.getSourceMatchAddress(),
			validator.getDestinationMatchAddress());
		VTMarkupItem markupItem = validator.searchForMarkupItem(match);

		return (markupItem.getStatus() == VTMarkupItemStatus.SAME);
	}

	protected void doTestFindAndDoNothingOnApplyOfSameMarkupItem(
			TestDataProviderAndValidator validator) throws Exception {

		VTSessionDB session = createNewSession();
		VTMatch match = createMatchSetWithOneMatch(session, validator.getSourceMatchAddress(),
			validator.getDestinationMatchAddress());
		VTMarkupItem markupItem = validator.searchForMarkupItem(match);

		boolean sameMarkup = doCheckForSameMarkupItem(validator);

		//
		// verify we cannot unapply before we have applied
		//
		List<VTMarkupItem> markupItems = new ArrayList<>();
		Address destinationApplyAddress = validator.getDestinationApplyAddress();
		markupItem.setDefaultDestinationAddress(destinationApplyAddress, TEST_ADDRESS_SOURCE);
		markupItems.add(markupItem);

		VtTask task = new UnapplyMarkupItemTask(session, null, markupItems);
		runTask(session, task);
		// In the GUI the apply task won't get called if same. For now, don't do action if same.
		// Seems like markupItemImpl.apply() should do nothing if same, but it applies anyway.
		if (!sameMarkup) {
			//
			// verify we can not apply
			//
			VTMarkupItemApplyActionType applyAction = validator.getApplyAction();
			if (applyAction != null) {
				task = new ApplyMarkupItemTask(session, markupItems, validator.getOptions());
				runTask(session, task);
				assertEquals("The markup item was applied when it should not have been.",
					VTMarkupItemStatus.SAME, markupItem.getStatus());
			}
		}
	}

	protected void doTestFindAndApplyMarkupItem_ApplyFails(TestDataProviderAndValidator validator)
			throws Exception {

		VTSessionDB session = createNewSession();
		VTMatch match = createMatchSetWithOneMatch(session, validator.getSourceMatchAddress(),
			validator.getDestinationMatchAddress());
		VTMarkupItem markupItem = validator.searchForMarkupItem(match);

		//
		// verify we cannot unapply before we have applied
		//
		List<VTMarkupItem> markupItems = new ArrayList<>();
		Address destinationAddress = addr();
		markupItem.setDefaultDestinationAddress(destinationAddress, TEST_ADDRESS_SOURCE);
		markupItems.add(markupItem);

		VtTask task = new UnapplyMarkupItemTask(session, null, markupItems);
		runTask(session, task);

		//
		// verify that calling apply still leaves us in an unapplied state
		//
		task = new ApplyMarkupItemTask(session, markupItems, validator.getOptions());
		runTask(session, task);

		assertEquals("The markup item status was not correctly set",
			VTMarkupItemStatus.FAILED_APPLY, markupItem.getStatus());
		validator.assertUnapplied();
	}

	protected void doTestFindNoMarkupItem(TestDataProviderAndValidator validator) throws Exception {

		VTSessionDB session = createNewSession();
		VTMatch match = createMatchSetWithOneMatch(session, validator.getSourceMatchAddress(),
			validator.getDestinationMatchAddress());
		VTMarkupItem markupItem = validator.searchForMarkupItem(match);

		//
		// verify that there isn't a markupItem
		//
		assertNull(markupItem);
	}

//==================================================================================================
// Utility Methods
//==================================================================================================

	protected String getNonDynamicName() {
		return "." + ++nameCounter + "." + getRandomString().replaceAll("_", "");
	}

	protected VTSessionDB createNewSession() throws Exception {
		return VTSessionDB.createVTSession(testName.getMethodName() + " - Test Match Set Manager",
			sourceProgram, destinationProgram, this);
	}

	protected static VTMatch createMatchSetWithOneMatch(VTSessionDB db, Address sourceAddress,
			Address destinationAddress) throws Exception {
		int testTransactionID = 0;
		try {
			testTransactionID = db.startTransaction("Test Match Set Setup");
			VTMatchInfo matchInfo = createRandomMatch(sourceAddress, destinationAddress, db);
			VTMatchSet matchSet = db.createMatchSet(
				createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));
			VTMatch addedMatch = matchSet.addMatch(matchInfo);

			// Association markupItemManger expects all markups to be generated though it.
			// Call it to put it in a good state.
			VTAssociation association = addedMatch.getAssociation();
			association.getMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR);

			return addedMatch;
		}
		finally {
			db.endTransaction(testTransactionID, true);
		}
	}

	private void runTask(VTSession session, VtTask task) {
		int id = session.startTransaction("test");
		try {
			task.run(TaskMonitor.DUMMY);
		}
		finally {
			session.endTransaction(id, true);
		}

	}
}
