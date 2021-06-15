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
import static org.junit.Assert.*;

import java.util.*;

import org.apache.logging.log4j.*;
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.After;
import org.junit.Before;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.feature.vt.api.correlator.program.ExactMatchInstructionsProgramCorrelatorFactory;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.FunctionSignatureMarkupType;
import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.gui.VTTestEnv;
import ghidra.feature.vt.gui.plugin.AddressCorrelatorManager;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.task.*;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.database.symbol.VariableSymbolDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.AddressCorrelation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractFunctionSignatureMarkupTest
		extends AbstractGhidraHeadedIntegrationTest {

	// Default Apply Markup Options
	// ============================
	// Data Match Data Type .......... = Replace Undefined Data Only
	// End of Line Comment ........... = Add To Existing
	// Function Call Fixup ........... = Replace
	// Function Calling Convention ... = Replace If Same Language
	// Function Inline ............... = Replace
	// Function Name ................. = Replace Always
	// Function No Return ............ = Replace
	// Function Parameter Comments ... = Add To Existing
	// Function Parameter Data Types . = Replace Undefined Data Types Only
	// Function Parameter Names ...... = User Priority Replace
	// Function Return Type .......... = Replace Undefined Data Types Only
	// Function Signature ............ = Replace When Same Parameter Count
	// Function Var Args ............. = Replace
	// Labels ........................ = Add
	// Plate Comment ................. = Add To Existing
	// Post Comment .................. = Add To Existing
	// Pre Comment ................... = Add To Existing
	// Repeatable Comment ............ = Add To Existing
	// Set Excluded Markup Items To Ignored ... = false
	// Set Incomplete Markup Items To Ignored . = false

	//  addPerson 004011a0   FUN... 004011a0    2 params
	//  call_Strncpy 00401300   FUN... 00401310    3 params w/ matching types
	//  Canary_Tester_... 0040131c   FUN... 0040132c    1 param & identical signature

	protected static final String TEST_SOURCE_PROGRAM_NAME = "VersionTracking/WallaceSrc";
	protected static final String TEST_DESTINATION_PROGRAM_NAME = "VersionTracking/WallaceVersion2";

	protected VTTestEnv vtTestEnv;
	protected VTProgramCorrelator correlator;
	protected Program sourceProgram;
	protected Program destinationProgram;
	protected VTController controller;
	protected VTSession session;
	protected Address sourceAddress;
	protected Address destinationAddress;
	protected VTMatch testMatch;
	protected Function sourceFunction;
	protected Function destinationFunction;

	@Before
	public void setUp() throws Exception {

		vtTestEnv = new VTTestEnv();
		session = vtTestEnv.createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		try {
			ExactMatchInstructionsProgramCorrelatorFactory factory =
				new ExactMatchInstructionsProgramCorrelatorFactory();
			correlator = vtTestEnv.correlate(factory, null, TaskMonitor.DUMMY);
		}
		catch (Exception e) {
			failWithException("Exception correlating exact instruction matches", e);
		}
		sourceProgram = vtTestEnv.getSourceProgram();
		disableAutoAnalysis(sourceProgram);

		destinationProgram = vtTestEnv.getDestinationProgram();
		disableAutoAnalysis(destinationProgram);

		controller = vtTestEnv.getVTController();
		vtTestEnv.showTool();

		Logger functionLogger = LogManager.getLogger(FunctionDB.class);
		Configurator.setLevel(functionLogger.getName(), Level.TRACE);

		Logger variableLogger = LogManager.getLogger(VariableSymbolDB.class);
		Configurator.setLevel(variableLogger.getName(), Level.TRACE);
	}

	private void disableAutoAnalysis(Program program) {
		// we must cheat to do this since this is not intended
		// to be used outside of the analysis thread
		setInstanceField("ignoreChanges", AutoAnalysisManager.getAnalysisManager(program),
			Boolean.TRUE);
	}

	@After
	public void tearDown() throws Exception {
		sourceProgram = null;
		destinationProgram = null;
		session = null;
		controller = null;
		correlator = null;
		vtTestEnv.dispose();

	}

	public static void setApplyMarkupOptionsToDefaults(ToolOptions applyOptions) {
		applyOptions.setEnum(DATA_MATCH_DATA_TYPE, DEFAULT_OPTION_FOR_DATA_MATCH_DATA_TYPE);
		applyOptions.setEnum(FUNCTION_NAME, DEFAULT_OPTION_FOR_FUNCTION_NAME);
		applyOptions.setEnum(FUNCTION_SIGNATURE, DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE);
		applyOptions.setEnum(CALLING_CONVENTION, DEFAULT_OPTION_FOR_CALLING_CONVENTION);
		applyOptions.setEnum(INLINE, DEFAULT_OPTION_FOR_INLINE);
		applyOptions.setEnum(NO_RETURN, DEFAULT_OPTION_FOR_NO_RETURN);
		applyOptions.setEnum(VAR_ARGS, DEFAULT_OPTION_FOR_VAR_ARGS);
		applyOptions.setEnum(CALL_FIXUP, DEFAULT_OPTION_FOR_CALL_FIXUP);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, DEFAULT_OPTION_FOR_FUNCTION_RETURN_TYPE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, DEFAULT_OPTION_FOR_PARAMETER_DATA_TYPES);
		applyOptions.setEnum(PARAMETER_NAMES, DEFAULT_OPTION_FOR_PARAMETER_NAMES);
		applyOptions.setEnum(HIGHEST_NAME_PRIORITY, DEFAULT_OPTION_FOR_HIGHEST_NAME_PRIORITY);
		applyOptions.setBoolean(PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY,
			DEFAULT_OPTION_FOR_PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY);
		applyOptions.setEnum(PARAMETER_COMMENTS, DEFAULT_OPTION_FOR_PARAMETER_COMMENTS);
		applyOptions.setEnum(LABELS, DEFAULT_OPTION_FOR_LABELS);
		applyOptions.setEnum(PLATE_COMMENT, DEFAULT_OPTION_FOR_PLATE_COMMENTS);
		applyOptions.setEnum(PRE_COMMENT, DEFAULT_OPTION_FOR_PRE_COMMENTS);
		applyOptions.setEnum(END_OF_LINE_COMMENT, DEFAULT_OPTION_FOR_EOL_COMMENTS);
		applyOptions.setEnum(REPEATABLE_COMMENT, DEFAULT_OPTION_FOR_REPEATABLE_COMMENTS);
		applyOptions.setEnum(POST_COMMENT, DEFAULT_OPTION_FOR_POST_COMMENTS);
	}

	public static void setApplyMarkupOptionsToReplace(ToolOptions applyOptions) {
		applyOptions.setEnum(DATA_MATCH_DATA_TYPE, ReplaceDataChoices.REPLACE_ALL_DATA);
		applyOptions.setEnum(LABELS, LabelChoices.REPLACE_ALL);
		applyOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.REPLACE_ALWAYS);
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.NAME_MATCH);
		applyOptions.setEnum(CALL_FIXUP, ReplaceChoices.REPLACE);
		applyOptions.setEnum(VAR_ARGS, ReplaceChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(HIGHEST_NAME_PRIORITY,
			HighestSourcePriorityChoices.USER_PRIORITY_HIGHEST);
		applyOptions.setBoolean(PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY, true);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.OVERWRITE_EXISTING);
		applyOptions.setEnum(PLATE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		applyOptions.setEnum(PRE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		applyOptions.setEnum(END_OF_LINE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		applyOptions.setEnum(REPEATABLE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		applyOptions.setEnum(POST_COMMENT, CommentChoices.OVERWRITE_EXISTING);
	}

	public static void setApplyMarkupOptionsToAdd(ToolOptions applyOptions) {
		applyOptions.setEnum(DATA_MATCH_DATA_TYPE, ReplaceDataChoices.REPLACE_ALL_DATA);
		applyOptions.setEnum(LABELS, LabelChoices.ADD);
		applyOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.ADD);
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.NAME_MATCH);
		applyOptions.setEnum(CALL_FIXUP, ReplaceChoices.REPLACE);
		applyOptions.setEnum(VAR_ARGS, ReplaceChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(HIGHEST_NAME_PRIORITY,
			HighestSourcePriorityChoices.USER_PRIORITY_HIGHEST);
		applyOptions.setBoolean(PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY, true);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(PLATE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(PRE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(END_OF_LINE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(REPEATABLE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(POST_COMMENT, CommentChoices.APPEND_TO_EXISTING);
	}

//==================================================================================================
// Helper Methods
//==================================================================================================

	protected void runTask(final VtTask task) {
		waitForBusyTool(vtTestEnv.getTool());
		Msg.debug(this, "runTask(): " + task.getTaskTitle() + "\n\n");
		controller.runVTTask(task);
		waitForSwing();
		destinationProgram.flushEvents();
		waitForSwing();
		Msg.debug(this, "\tdone task: " + task.getTaskTitle() + "\n\n");
	}

	protected String dumpStatus(List<VTMarkupItem> individualItems) {
		StringBuilder buffer = new StringBuilder();
		int index = 0;
		for (VTMarkupItem vtMarkupItem : individualItems) {
			buffer.append(
				"\nmarkupItem(" + (index++) + ") status = " + vtMarkupItem.getStatus().toString() +
					"  " + vtMarkupItem.getMarkupType().getDisplayName() + ".");
		}
		return buffer.toString();
	}

	protected void checkMatchStatus(VTAssociationStatus expectedStatus) {
		assertEquals(expectedStatus, testMatch.getAssociation().getStatus());
	}

	protected void useMatch(String sourceAddressString, String destinationAddressString) {
		sourceAddress = addr(sourceAddressString, sourceProgram);
		destinationAddress = addr(destinationAddressString, destinationProgram);

		testMatch = getMatch(sourceAddress, destinationAddress);
		assertNotNull(testMatch);

		sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		assertNotNull(sourceFunction);
		destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		assertNotNull(destinationFunction);
	}

	protected void checkDestinationParameterNameSourceTypes(SourceType[] sourceTypes) {
		int parameterCount = destinationFunction.getParameterCount();
		assertEquals("Destination function has wrong number of parameters. ", sourceTypes.length,
			parameterCount);
		for (int i = 0; i < parameterCount; i++) {
			assertEquals("Parameter " + i + " has wrong source type. ", sourceTypes[i],
				destinationFunction.getParameter(i).getSource());
		}
	}

	protected SourceType[] getParameterSourceTypes(Function function) {
		int parameterCount = function.getParameterCount();
		SourceType[] sourceTypes = new SourceType[parameterCount];
		for (int i = 0; i < parameterCount; i++) {
			sourceTypes[i] = function.getParameter(i).getSource();
		}
		return sourceTypes;
	}

	protected void checkSignatures(String expectedSourceSignature,
			String expectedDestinationSignature) {

		final String[] sourceStringBox = new String[1];
		final String[] destinationStringBox = new String[1];

		runSwing(() -> {
			sourceStringBox[0] = sourceFunction.getPrototypeString(false, false);
			destinationStringBox[0] = destinationFunction.getPrototypeString(false, false);
		});

		assertEquals(expectedSourceSignature, sourceStringBox[0]);
		assertEquals(expectedDestinationSignature, destinationStringBox[0]);
	}

	protected void checkFunctionSignatureStatus(VTMatch match, VTMarkupItemStatus expectedStatus) {
		VTMarkupItem markupItem = getFunctionSignatureMarkup(match);
		if (expectedStatus == null && markupItem == null) {
			return;
		}
		assertNotNull(markupItem);
		checkMarkupStatus(markupItem, expectedStatus);
	}

// There is no longer a NoReturn markup.
//	protected void checkNoReturnStatus(VTMatch match, VTMarkupItemStatus expectedStatus) {
//		VTMarkupItem markupItem = getNoReturnMarkup(match);
//		if (expectedStatus == null && markupItem == null) {
//			return;
//		}
//		assertNotNull(markupItem);
//		checkMarkupStatus(markupItem, expectedStatus);
//	}

	protected void checkParameterComments(Function function, int ordinal, String expectedComment) {
		Parameter parameter = function.getParameter(ordinal);
		String actualComment = parameter.getComment();
		assertEquals(expectedComment, actualComment);
	}

	protected void checkParameterName(Function function, int ordinal, String expectedName,
			SourceType expectedSource) {
		Parameter parameter = function.getParameter(ordinal);
		assertEquals(expectedName, parameter.getName());
		assertEquals(expectedSource, parameter.getSource());
	}

// There is no longer a ParameterNames markup
//	protected void checkParameterNamesStatus(VTMatch match, VTMarkupItemStatus expectedStatus) {
//		VTMarkupItem markupItem = getParameterNamesMarkup(match);
//		if (expectedStatus == null && markupItem == null) {
//			return;
//		}
//		assertNotNull(markupItem);
//		checkMarkupStatus(markupItem, expectedStatus);
//	}

	protected void checkMarkupStatus(List<VTMarkupItem> markupItems,
			VTMarkupItemStatus expectedStatus) {
		for (VTMarkupItem vtMarkupItem : markupItems) {
			checkMarkupStatus(vtMarkupItem, expectedStatus);
		}
	}

	protected void checkMarkupStatus(VTMarkupItem vtMarkupItem, VTMarkupItemStatus expectedStatus) {
		assertEquals(
			vtMarkupItem.getMarkupType().getDisplayName() + " with source of " +
				vtMarkupItem.getSourceAddress().toString() + " has wrong status ",
			expectedStatus, vtMarkupItem.getStatus());
	}

	protected void checkCallingConvention(String sourceCallingConvention,
			String destinationCallingConvention) {
		PrototypeModel scc = sourceFunction.getCallingConvention();
		PrototypeModel dcc = destinationFunction.getCallingConvention();
		assertEquals(sourceCallingConvention,
			(scc == null) ? Function.UNKNOWN_CALLING_CONVENTION_STRING : scc.getName());
		assertEquals(destinationCallingConvention,
			(dcc == null) ? Function.UNKNOWN_CALLING_CONVENTION_STRING : dcc.getName());
	}

	protected void checkCallFixup(String sourceCallFixup, String destinationCallFixup) {
		assertEquals(sourceCallFixup, sourceFunction.getCallFixup());
		assertEquals(destinationCallFixup, destinationFunction.getCallFixup());
	}

	protected void checkInlineFlags(boolean sourceInlineFlag, boolean destinationInlineFlag) {
		assertEquals(sourceInlineFlag, sourceFunction.isInline());
		assertEquals(destinationInlineFlag, destinationFunction.isInline());
	}

	protected void checkNoReturnFlags(boolean sourceNoReturnFlag, boolean destinationNoReturnFlag) {
		assertEquals(sourceNoReturnFlag, sourceFunction.hasNoReturn());
		assertEquals(destinationNoReturnFlag, destinationFunction.hasNoReturn());
	}

	protected VTMarkupItem getFunctionSignatureMarkup(VTMatch match) {
		MatchInfo matchInfo = controller.getMatchInfo(match);
		Collection<VTMarkupItem> appliableMarkupItems =
			matchInfo.getAppliableMarkupItems(TaskMonitor.DUMMY);
		for (VTMarkupItem vtMarkupItem : appliableMarkupItems) {
			if (vtMarkupItem.getMarkupType() instanceof FunctionSignatureMarkupType) {
				return vtMarkupItem;
			}
		}
		return null;
	}

	protected List<VTMarkupItem> getSpecificTypeOfMarkup(
			Class<? extends VTMarkupType> markupTypeClass, VTMatch match, boolean onlyUnapplied) {
		List<VTMarkupItem> list = new ArrayList<>();
		MatchInfo matchInfo = controller.getMatchInfo(match);
		Collection<VTMarkupItem> appliableMarkupItems =
			matchInfo.getAppliableMarkupItems(TaskMonitor.DUMMY);
		for (VTMarkupItem vtMarkupItem : appliableMarkupItems) {
			if (vtMarkupItem.getMarkupType().getClass() == markupTypeClass) {
				if (!onlyUnapplied || vtMarkupItem.getStatus() == VTMarkupItemStatus.UNAPPLIED) {
					list.add(vtMarkupItem);
				}
			}
		}
		return list;
	}

	protected VTMatch getMatch(Address source, Address destination) {
		List<VTMatchSet> matchSets = session.getMatchSets();
		// Get matchSet 2 since 0 is manual matches and 1 is implied matches.
		assertTrue("Test not setup correctly; expected at least 3 match sets",
			matchSets.size() > 1);
		VTMatchSet vtMatchSet = matchSets.get(2);
		assertNotNull(vtMatchSet);
		Collection<VTMatch> matches = vtMatchSet.getMatches(source, destination);
		VTMatch[] matchesArray = matches.toArray(new VTMatch[matches.size()]);
		assertTrue(matchesArray.length > 0);
		VTMatch vtMatch = matchesArray[0];
		return vtMatch;
	}

	protected void removeParameter(Function function, int ordinal) {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Remove Parameter: " + ordinal);
			function.removeParameter(ordinal);
		}
		finally {
			program.endTransaction(transaction, true);
		}
		waitOnPossibleBackgroundProcessing();
	}

	protected void setReturnType(Function function, DataType returnType, SourceType source)
			throws InvalidInputException {
		Program program = function.getProgram();
		int transaction = -1;
		boolean commit = false;
		try {
			transaction =
				program.startTransaction("Test - Set Return Type: " + returnType.getName());
			function.setReturnType(returnType, source);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		waitOnPossibleBackgroundProcessing();
	}

	protected void setFunctionName(Function function, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Set Function Name: " + name);
			function.setName(name, source);
		}
		finally {
			program.endTransaction(transaction, true);
		}
		waitOnPossibleBackgroundProcessing();
	}

	protected void setParameterDataType(Function function, int ordinal, DataType dataType,
			SourceType source) throws InvalidInputException {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Set Parameter Data Type: " + ordinal);
			Parameter parameter = function.getParameter(ordinal);
			parameter.setDataType(dataType, source);
		}
		finally {
			program.endTransaction(transaction, true);
		}
		waitOnPossibleBackgroundProcessing();
	}

	protected void setParameterName(Function function, int ordinal, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Set Parameter Name: " + ordinal);
			Parameter parameter = function.getParameter(ordinal);
			parameter.setName(name, source);
		}
		finally {
			program.endTransaction(transaction, true);
		}
		waitOnPossibleBackgroundProcessing();
	}

	protected void setParameterComment(Function function, int ordinal, String comment) {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Set Parameter Comment: " + ordinal);
			Parameter parameter = function.getParameter(ordinal);
			parameter.setComment(comment);
		}
		finally {
			program.endTransaction(transaction, true);
		}
		waitOnPossibleBackgroundProcessing();
	}

	protected void setCallingConvention(Function function, String callingConvention)
			throws InvalidInputException {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction =
				program.startTransaction("Test - Setting CallingConvention: " + callingConvention);
			function.setCallingConvention(callingConvention);
		}
		finally {
			program.endTransaction(transaction, true);
		}
		waitOnPossibleBackgroundProcessing();
	}

	protected void setCallFixup(Function function, String callFixup) {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Setting CallFixup: " + callFixup);
			function.setCallFixup(callFixup);
		}
		finally {
			program.endTransaction(transaction, true);
		}
		waitOnPossibleBackgroundProcessing();
	}

	protected void setVarArgs(Function function, boolean hasVarArgs) {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Setting VarArgs: " + hasVarArgs);
			function.setVarArgs(hasVarArgs);
		}
		finally {
			program.endTransaction(transaction, true);
		}
		waitOnPossibleBackgroundProcessing();
	}

	protected void setInline(Function function, boolean isInline) {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Setting Inline Flag: " + isInline);
			function.setInline(isInline);
		}
		finally {
			program.endTransaction(transaction, true);
		}
		waitOnPossibleBackgroundProcessing();
	}

	protected void setNoReturn(Function function, boolean hasNoReturn) {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Setting No Return Flag: " + hasNoReturn);
			function.setNoReturn(hasNoReturn);
		}
		finally {
			program.endTransaction(transaction, true);
		}
		waitOnPossibleBackgroundProcessing();
	}

	private void waitOnPossibleBackgroundProcessing() {
		waitForSwing();
		waitForBusyTool(vtTestEnv.getTool());
	}

	protected void applyFunctionSignatureMarkup(List<VTMarkupItem> functionSignatureMarkupItems) {
		ApplyMarkupItemTask task =
			new ApplyMarkupItemTask(session, functionSignatureMarkupItems, controller.getOptions());
		runTask(task);
		try {
			waitForTasks();
		}
		catch (Exception e) {
			failWithException(e.getMessage(), e);
		}
	}

	protected void forceFunctionSignatureMarkup(List<VTMarkupItem> functionSignatureMarkupItems) {
		ForceApplyMarkupItemTask task = new ForceApplyMarkupItemTask(session,
			functionSignatureMarkupItems, controller.getOptions());
		runTask(task);
	}

	protected void unapplyFunctionSignatureMarkup(List<VTMarkupItem> functionSignatureMarkupItems) {
		//
		// Now test the unapply of the signature
		//
		AddressCorrelatorManager addressCorrelatorManager =
			new AddressCorrelatorManager(controller);
		AddressCorrelation correlation =
			addressCorrelatorManager.getCorrelator(sourceFunction, destinationFunction);
		UnapplyMarkupItemTask unapplySignatureTask =
			new UnapplyMarkupItemTask(session, correlation, functionSignatureMarkupItems);
		runTask(unapplySignatureTask);
	}
}
