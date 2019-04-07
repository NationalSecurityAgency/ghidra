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
package ghidra.feature.vt.api;

import static ghidra.feature.vt.db.VTTestUtils.*;
import static ghidra.feature.vt.gui.util.VTOptionDefines.*;
import static org.junit.Assert.*;

import java.awt.Window;
import java.util.*;

import org.junit.*;

import docking.ActionContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.CommentMarkupType;
import ghidra.feature.vt.gui.actions.ApplyBlockedMatchAction;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchContext;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchTableProvider;
import ghidra.feature.vt.gui.task.*;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.test.*;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.*;

public class VTMatchApplyTest extends AbstractGhidraHeadedIntegrationTest {

	private Undefined4DataType undefined4DataType = new Undefined4DataType();
	private PointerDataType stringPointerDataType = new PointerDataType(new StringDataType());
	private DWordDataType dWordDataType = new DWordDataType();
	private FloatDataType floatDataType = new FloatDataType();
	private TestEnv env;
	private PluginTool tool;
	private VTController controller;
	private VTSessionDB session;
	private ProgramDB sourceProgram;
	private ProgramDB destinationProgram;
	private VTPlugin plugin;

	// TODO: debug
	private DomainObjectListenerRecorder eventRecorder = new DomainObjectListenerRecorder();

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();

		ClassicSampleX86ProgramBuilder sourceBuilder =
			new ClassicSampleX86ProgramBuilder("notepadSrc", true, this);
		sourceProgram = sourceBuilder.getProgram();

		ClassicSampleX86ProgramBuilder destinationBuilder =
			new ClassicSampleX86ProgramBuilder("notepadDest", true, this);
		destinationProgram = destinationBuilder.getProgram();
		destinationProgram.addListener(eventRecorder);

		setupPrograms(sourceBuilder, destinationBuilder);

		tool = env.getTool();

		tool.addPlugin(VTPlugin.class.getName());
		plugin = getPlugin(tool, VTPlugin.class);
		controller = new VTControllerImpl(plugin);

		session =
			VTSessionDB.createVTSession(testName.getMethodName() + " - Test Match Set Manager",
				sourceProgram, destinationProgram, this);

		runSwing(() -> controller.openVersionTrackingSession(session));

		setAllOptionsToDoNothing();
	}

	private void setupPrograms(ClassicSampleX86ProgramBuilder sourceBuilder,
			ClassicSampleX86ProgramBuilder destinationBuilder) throws Exception {

		createFunction_01003f9e(sourceBuilder);
		createFunction_01003f9e(destinationBuilder);

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

	private void setAllOptionsToDoNothing() {
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(VTOptionDefines.PLATE_COMMENT, CommentChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.PRE_COMMENT, CommentChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.END_OF_LINE_COMMENT, CommentChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.REPEATABLE_COMMENT, CommentChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.POST_COMMENT, CommentChoices.EXCLUDE);
//		applyOptions.putEnum(VTOptionDefines.DATA_REFERENCE, LabelChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.FUNCTION_NAME, FunctionNameChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.FUNCTION_SIGNATURE, FunctionSignatureChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.INLINE, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.CALLING_CONVENTION, CallingConventionChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.CALL_FIXUP, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.VAR_ARGS, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.PARAMETER_NAMES, SourcePriorityChoices.EXCLUDE);
		// Since this is simply doing an exclude, it doesn't need to set parameter name's
		// highest priority or replace if same source flag.
		applyOptions.setEnum(VTOptionDefines.PARAMETER_COMMENTS, CommentChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE, ReplaceDataChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.LABELS, LabelChoices.EXCLUDE);
//		applyOptions.putEnum(VTOptionDefines.PARAMETER_DATA_TYPE, ReplaceChoices.EXCLUDE);
//		applyOptions.putEnum(VTOptionDefines.PARAMETER_NAME, ReplaceDefaultChoices.EXCLUDE);
//		applyOptions.putEnum(VTOptionDefines.PARAMETER_COMMENT, CommentChoices.EXCLUDE);
//		applyOptions.putEnum(VTOptionDefines.LOCAL_VARIABLE_DATA_TYPE, ReplaceChoices.EXCLUDE);
//		applyOptions.putEnum(VTOptionDefines.LOCAL_VARIABLE_NAME, ReplaceDefaultChoices.EXCLUDE);
//		applyOptions.putEnum(VTOptionDefines.LOCAL_VARIABLE_COMMENT, CommentChoices.EXCLUDE);
	}

	@After
	public void tearDown() throws Exception {
		waitForBusyTool(tool);
		destinationProgram.flushEvents();
		waitForSwing();

		env.dispose();

		if (sourceProgram != null) {
			sourceProgram.release(this);
		}
		if (destinationProgram != null) {
			destinationProgram.release(this);
		}
	}

	@Test
	public void testApplyMatchEOLComments_Ignore() throws Exception {

		doTestApplyCommentMatch_Ignore(CodeUnit.EOL_COMMENT, VTOptionDefines.END_OF_LINE_COMMENT,
			CommentChoices.EXCLUDE);
	}

	@Test
	public void testApplyMatchPreComments_Ignore() throws Exception {

		doTestApplyCommentMatch_Ignore(CodeUnit.PRE_COMMENT, VTOptionDefines.PRE_COMMENT,
			CommentChoices.EXCLUDE);
	}

	@Test
	public void testApplyMatchPostComments_Ignore() throws Exception {

		doTestApplyCommentMatch_Ignore(CodeUnit.POST_COMMENT, VTOptionDefines.POST_COMMENT,
			CommentChoices.EXCLUDE);
	}

	@Test
	public void testApplyMatchPlateComments_Ignore() throws Exception {

		doTestApplyCommentMatch_Ignore(CodeUnit.PLATE_COMMENT, VTOptionDefines.PLATE_COMMENT,
			CommentChoices.EXCLUDE);
	}

	@Test
	public void testApplyMatchRepeatableComments_Ignore() throws Exception {

		doTestApplyCommentMatch_Ignore(CodeUnit.REPEATABLE_COMMENT,
			VTOptionDefines.REPEATABLE_COMMENT, CommentChoices.EXCLUDE);
	}

	private void doTestApplyCommentMatch_Ignore(int codeUnitCommentType,
			String vtCommentOptionDefine, CommentChoices commentChoice) throws Exception {
		String sourceComment = "Hi mom replace";
		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		Address destinationAddress = addr("0x01002cf5", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Address commentAddress = addr("0x01002d06", sourceProgram);
		setComment(sourceProgram, commentAddress, codeUnitCommentType, sourceComment);

		// comment choices
		controller.getOptions().setEnum(vtCommentOptionDefine, commentChoice);

		// starting destination comment value
		Listing destinationListing = destinationProgram.getListing();
		String currentComment = destinationListing.getComment(codeUnitCommentType, commentAddress);
		assertNull("Found comment where there should be none!", currentComment);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		currentComment = destinationListing.getComment(codeUnitCommentType, commentAddress);
		assertNull("Comment was applied when the options were set to IGNORE", currentComment);

		//
		// Now test the clear tag
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);
		currentComment = destinationListing.getComment(codeUnitCommentType, commentAddress);
		assertNull("Found a comment after executing unapply", currentComment);
	}

	@Test
	public void testApplyMatchEOLComments_Append() throws Exception {

		doTestApplyCommentMatch_Append(CodeUnit.EOL_COMMENT, VTOptionDefines.END_OF_LINE_COMMENT,
			CommentChoices.APPEND_TO_EXISTING);
	}

	@Test
	public void testApplyMatchPreComments_Append() throws Exception {

		doTestApplyCommentMatch_Append(CodeUnit.PRE_COMMENT, VTOptionDefines.PRE_COMMENT,
			CommentChoices.APPEND_TO_EXISTING);
	}

	@Test
	public void testApplyMatchPostComments_Append() throws Exception {

		doTestApplyCommentMatch_Append(CodeUnit.POST_COMMENT, VTOptionDefines.POST_COMMENT,
			CommentChoices.APPEND_TO_EXISTING);
	}

	@Test
	public void testApplyMatchPlateComments_Append() throws Exception {

		doTestApplyCommentMatch_Append(CodeUnit.PLATE_COMMENT, VTOptionDefines.PLATE_COMMENT,
			CommentChoices.APPEND_TO_EXISTING);
	}

	@Test
	public void testApplyMatchRepeatableComments_Append() throws Exception {

		doTestApplyCommentMatch_Append(CodeUnit.REPEATABLE_COMMENT,
			VTOptionDefines.REPEATABLE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
	}

	private void doTestApplyCommentMatch_Append(int codeUnitCommentType,
			String vtCommentOptionDefine, CommentChoices commentChoice) throws Exception {
		String sourceComment = "Hi mom replace";
		String destinationComment = "Hi dad replace";

		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		Address destinationAddress = addr("0x01002cf5", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

// TODO this address doesn't exist because the function has no body

		// force known values for the test
		Address commentAddress = addr("0x01002d06", sourceProgram);
		setComment(sourceProgram, commentAddress, codeUnitCommentType, sourceComment);
		setComment(destinationProgram, commentAddress, codeUnitCommentType, destinationComment);

		// comment choices
		controller.getOptions().setEnum(vtCommentOptionDefine, CommentChoices.APPEND_TO_EXISTING);

		// starting destination comment value
		Listing destinationListing = destinationProgram.getListing();

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		String expectedComment = destinationComment + "\n" + sourceComment;
		String comment = destinationListing.getComment(codeUnitCommentType, commentAddress);

		assertEquals("Comment was not applied", expectedComment, comment);

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);
		comment = destinationListing.getComment(codeUnitCommentType, commentAddress);
		assertEquals("Comment was not unapplied", destinationComment, comment);
	}

	@Test
	public void testApplyMatchEOLComments_Overwrite() throws Exception {

		doTestApplyCommentMatch_Overwrite(CodeUnit.EOL_COMMENT, VTOptionDefines.END_OF_LINE_COMMENT,
			CommentChoices.OVERWRITE_EXISTING);
	}

	@Test
	public void testApplyMatchPreComments_Overwrite() throws Exception {

		doTestApplyCommentMatch_Overwrite(CodeUnit.PRE_COMMENT, VTOptionDefines.PRE_COMMENT,
			CommentChoices.OVERWRITE_EXISTING);
	}

	@Test
	public void testApplyMatchPostComments_Overwrite() throws Exception {

		doTestApplyCommentMatch_Overwrite(CodeUnit.POST_COMMENT, VTOptionDefines.POST_COMMENT,
			CommentChoices.OVERWRITE_EXISTING);
	}

	@Test
	public void testApplyMatchPlateComments_Overwrite() throws Exception {

		doTestApplyCommentMatch_Overwrite(CodeUnit.PLATE_COMMENT, VTOptionDefines.PLATE_COMMENT,
			CommentChoices.OVERWRITE_EXISTING);
	}

	@Test
	public void testApplyMatchRepeatableComments_Overwrite() throws Exception {

		doTestApplyCommentMatch_Overwrite(CodeUnit.REPEATABLE_COMMENT,
			VTOptionDefines.REPEATABLE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
	}

	private void doTestApplyCommentMatch_Overwrite(int codeUnitCommentType,
			String vtCommentOptionDefine, CommentChoices commentChoice) throws Exception {
		String sourceComment = "Hi mom replace";
		String destinationComment = "Hi dad replace";

		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		Address destinationAddress = addr("0x01002cf5", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Address sourceCommentAddress = addr("0x01002d06", sourceProgram);
		Address destinationCommentAddress = addr("0x01002d06", sourceProgram);
		setComment(sourceProgram, sourceCommentAddress, codeUnitCommentType, sourceComment);
		setComment(destinationProgram, destinationCommentAddress, codeUnitCommentType,
			destinationComment);

		// comment choices
		controller.getOptions().setEnum(vtCommentOptionDefine, commentChoice);

		// starting destination comment value
		Listing destinationListing = destinationProgram.getListing();

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		String expectedComment = sourceComment;
		String comment =
			destinationListing.getComment(codeUnitCommentType, destinationCommentAddress);
		assertEquals("Comment was not applied", expectedComment, comment);

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);
		comment = destinationListing.getComment(codeUnitCommentType, destinationCommentAddress);
		assertEquals("Comment was not unapplied", destinationComment, comment);
	}

	@Test
	public void testApplyMatchLabels_Ignore() throws Exception {

		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		Address destinationAddress = addr("0x01002cf5", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Address labelAddress = addr("0x01002d06", sourceProgram);
		addLabel(labelAddress, sourceProgram);
		Symbol destinationSymbol1 = addLabel(labelAddress, destinationProgram);

		// symbol/comment choices
		controller.getOptions().setEnum(VTOptionDefines.LABELS, LabelChoices.EXCLUDE);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		Symbol expectedSymbol = destinationSymbol1;
		SymbolTable symbolTable = destinationProgram.getSymbolTable();
		Symbol[] newSymbols = symbolTable.getSymbols(labelAddress);
		Symbol[] expectedSymbols = new Symbol[] { expectedSymbol };
		assertTrue("New label does not match the source label",
			SystemUtilities.isArrayEqual(expectedSymbols, newSymbols));

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		unapplyTask.run(TaskMonitorAdapter.DUMMY_MONITOR);
		newSymbols = symbolTable.getSymbols(labelAddress);
		expectedSymbols = new Symbol[] { destinationSymbol1 };
		assertTrue("New label does not match the source label",
			SystemUtilities.isArrayEqual(expectedSymbols, newSymbols));
	}

	@Test
	public void testApplyMatchLabels_ReplaceDefault() throws Exception {

		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		Address destinationAddress = addr("0x01002cf5", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Address sourceLabelAddress = addr("0x01002d06", sourceProgram);
		Address destinationLabelAddress = addr("0x01002d06", sourceProgram);
		Symbol sourceSymbol1 = addLabel(sourceLabelAddress, sourceProgram);
		Symbol destinationSymbol1 = addDefaultLabel(destinationLabelAddress, destinationProgram);

		// symbol/comment choices
		controller.getOptions().setEnum(VTOptionDefines.LABELS, LabelChoices.REPLACE_DEFAULT_ONLY);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		Symbol expectedSymbol = sourceSymbol1;
		SymbolTable symbolTable = destinationProgram.getSymbolTable();
		Symbol[] newSymbols = symbolTable.getSymbols(destinationLabelAddress);

		// we expect the source symbol and the non-default symbol that was already there
		Symbol[] expectedSymbols = new Symbol[] { expectedSymbol };
		assertTrue("New label does not match the source label",
			SystemUtilities.isArrayEqual(expectedSymbols, newSymbols));

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);
		newSymbols = symbolTable.getSymbols(destinationLabelAddress);
		expectedSymbols = new Symbol[] { destinationSymbol1 };
		assertTrue("New label does not match the source label",
			SystemUtilities.isArrayEqual(expectedSymbols, newSymbols));
	}

	@Test
	public void testApplyMatchLabels_ReplaceAll() throws Exception {

		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		Address destinationAddress = addr("0x01002cf5", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Address sourceLabelAddress = addr("0x01002d06", sourceProgram);
		Address destinationLabelAddress = addr("0x01002d06", sourceProgram);
		Symbol sourceSymbol1 = addLabel(sourceLabelAddress, sourceProgram);
		Symbol destinationSymbol1 = addLabel(destinationLabelAddress, destinationProgram);

		// symbol/comment choices
		controller.getOptions().setEnum(VTOptionDefines.LABELS, LabelChoices.REPLACE_ALL);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		Symbol expectedSymbol = sourceSymbol1;
		SymbolTable symbolTable = destinationProgram.getSymbolTable();
		Symbol[] newSymbols = symbolTable.getSymbols(destinationLabelAddress);
		Symbol[] expectedSymbols = new Symbol[] { expectedSymbol };
		assertTrue("New label does not match the source label",
			SystemUtilities.isArrayEqual(expectedSymbols, newSymbols));

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);
		newSymbols = symbolTable.getSymbols(destinationLabelAddress);
		expectedSymbols = new Symbol[] { destinationSymbol1 };
		assertTrue("New label does not match the source label",
			SystemUtilities.isArrayEqual(expectedSymbols, newSymbols));
	}

	@Test
	public void testApplyDataMatchDataType_Ignore() throws Exception {

		Address sourceAddress = addr("0x0100808c", sourceProgram);
		Address destinationAddress = addr("0x0100808c", destinationProgram);
		Listing destinationListing = destinationProgram.getListing();

		// force known values for the test
		DataType sourceDataType = new DWordDataType();
		DataType destinationDataType1 = new StringDataType();
		DataType destinationDataType2 = new WordDataType();
		setData(sourceDataType, 4, sourceAddress, sourceProgram);
		setData(destinationDataType1, 2, destinationAddress, destinationProgram);
		setData(destinationDataType2, 2, destinationAddress.add(2), destinationProgram);

		VTMatch match = createMatchSetWithOneDataMatch(session, sourceAddress, destinationAddress);

		// data type choices
		controller.getOptions().setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
			ReplaceDataChoices.EXCLUDE);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		VTAssociationStatus status = match.getAssociation().getStatus();
		assertEquals(VTAssociationStatus.ACCEPTED, status);
		checkDataMatchDataType(destinationDataType1, 2, destinationAddress, destinationListing);
		checkDataMatchDataType(destinationDataType2, 2, destinationAddress.add(2),
			destinationListing);
	}

	@Test
	public void testApplyDataMatchDataType_ReplaceUndefinedDataOnly_DoNothing() throws Exception {

		Address sourceAddress = addr("0x0100808c", sourceProgram);
		Address destinationAddress = addr("0x0100808c", destinationProgram);
		Listing destinationListing = destinationProgram.getListing();

		// force known values for the test
		DataType sourceDataType = new DWordDataType();
		DataType destinationDataType1 = new StringDataType();
		DataType destinationDataType2 = new WordDataType();
		setData(sourceDataType, 4, sourceAddress, sourceProgram);
		setData(destinationDataType1, 2, destinationAddress, destinationProgram);
		setData(destinationDataType2, 2, destinationAddress.add(2), destinationProgram);

		VTMatch match = createMatchSetWithOneDataMatch(session, sourceAddress, destinationAddress);

		// data type choice
		controller.getOptions().setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
			ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		VTAssociationStatus status = match.getAssociation().getStatus();
		assertEquals(VTAssociationStatus.ACCEPTED, status);
		checkDataMatchDataType(destinationDataType1, 2, destinationAddress, destinationListing);
		checkDataMatchDataType(destinationDataType2, 2, destinationAddress.add(2),
			destinationListing);
	}

	@Test
	public void testApplyDataMatchDataType_ReplaceUndefinedDataOnly_Success() throws Exception {

		Address sourceAddress = addr("0x0100808c", sourceProgram);
		Address destinationAddress = addr("0x0100808c", destinationProgram);
		Listing destinationListing = destinationProgram.getListing();

		// force known values for the test
		DataType sourceDataType = new DWordDataType();
		setData(sourceDataType, 4, sourceAddress, sourceProgram);

		VTMatch match = createMatchSetWithOneDataMatch(session, sourceAddress, destinationAddress);

		// data type choice
		controller.getOptions().setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
			ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		VTAssociationStatus status = match.getAssociation().getStatus();
		assertEquals(VTAssociationStatus.ACCEPTED, status);
		checkDataMatchDataType(sourceDataType, 4, destinationAddress, destinationListing);

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);

		status = match.getAssociation().getStatus();
		assertEquals(VTAssociationStatus.AVAILABLE, status);
		checkDataMatchDataType(DataType.DEFAULT, 1, destinationAddress, destinationListing);
		checkDataMatchDataType(DataType.DEFAULT, 1, destinationAddress.add(2), destinationListing);
	}

	@Test
	public void testApplyDataMatchDataType_ReplaceFirstDataOnly_DoNothing() throws Exception {

		Address sourceAddress = addr("0x0100808c", sourceProgram);
		Address destinationAddress = addr("0x0100808c", destinationProgram);
		Listing destinationListing = destinationProgram.getListing();

		// force known values for the test
		DataType sourceDataType = new DWordDataType();
		DataType destinationDataType1 = new StringDataType();
		DataType destinationDataType2 = new WordDataType();
		setData(sourceDataType, 4, sourceAddress, sourceProgram);
		setData(destinationDataType1, 2, destinationAddress, destinationProgram);
		setData(destinationDataType2, 2, destinationAddress.add(2), destinationProgram);

		VTMatch match = createMatchSetWithOneDataMatch(session, sourceAddress, destinationAddress);

		// data type choice
		controller.getOptions().setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		controller.runVTTask(task);

		VTAssociationStatus status = match.getAssociation().getStatus();
		assertEquals(VTAssociationStatus.ACCEPTED, status);
		checkDataMatchDataType(destinationDataType1, 2, destinationAddress, destinationListing);
		checkDataMatchDataType(destinationDataType2, 2, destinationAddress.add(2),
			destinationListing);
	}

	@Test
	public void testApplyDataMatchDataType_ReplaceFirstDataOnly_Success() throws Exception {

		Address sourceAddress = addr("0x0100808c", sourceProgram);
		Address destinationAddress = addr("0x0100808c", destinationProgram);
		Listing destinationListing = destinationProgram.getListing();

		// force known values for the test 
		DataType sourceDataType = new DWordDataType();
		DataType destinationDataType1 = new StringDataType();
		setData(sourceDataType, 4, sourceAddress, sourceProgram);
		setData(destinationDataType1, 2, destinationAddress, destinationProgram);

		VTMatch match = createMatchSetWithOneDataMatch(session, sourceAddress, destinationAddress);

		// data type choice 
		controller.getOptions().setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		VTAssociationStatus status = match.getAssociation().getStatus();
		assertEquals(VTAssociationStatus.ACCEPTED, status);
		checkDataMatchDataType(sourceDataType, 4, destinationAddress, destinationListing);

		// 
		// Now test the unapply 
		// 
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);

		status = match.getAssociation().getStatus();
		assertEquals(VTAssociationStatus.AVAILABLE, status);
		checkDataMatchDataType(destinationDataType1, 2, destinationAddress, destinationListing);
		checkDataMatchDataType(DataType.DEFAULT, 1, destinationAddress.add(2), destinationListing);
	}

	@Test
	public void testApplyDataMatchDataType_ReplaceAtInstruction_DoNothing() throws Exception {

		Address sourceAddress = addr("0x0100808c", sourceProgram);
		Address destinationAddress = addr("0x0100808c", destinationProgram);
		Listing destinationListing = destinationProgram.getListing();

		// force known values for the test 
		DataType sourceDataType = new DWordDataType();
		DataType destinationDataType1 = new StringDataType();
		setData(sourceDataType, 4, sourceAddress, sourceProgram);
		setData(destinationDataType1, 2, destinationAddress, destinationProgram);
		createInstruction(destinationAddress.add(2), destinationProgram, 2);

		VTMatch match = createMatchSetWithOneDataMatch(session, sourceAddress, destinationAddress);

		// data type choice 
		controller.getOptions().setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
			ReplaceDataChoices.REPLACE_ALL_DATA);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		VTAssociationStatus status = match.getAssociation().getStatus();
		assertEquals(VTAssociationStatus.ACCEPTED, status);
		checkDataMatchDataType(destinationDataType1, 2, destinationAddress, destinationListing);
	}

	private void createInstruction(Address address, ProgramDB program, int length) {
		int txID = program.startTransaction("Creating instruction");
		boolean commit = false;
		try {
			// Create instruction here. 
			DisassembleCommand cmd = new DisassembleCommand(address,
				new AddressSet(address, address.add(length)), false);
			cmd.applyTo(program);

			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}
	}

	@Test
	public void testApplyDataMatchDataType_Replace_Success() throws Exception {

		Address sourceAddress = addr("0x0100808c", sourceProgram);
		Address destinationAddress = addr("0x0100808c", destinationProgram);
		Listing destinationListing = destinationProgram.getListing();

		// force known values for the test
		DataType sourceDataType = new DWordDataType();
		DataType destinationDataType1 = new StringDataType();
		setData(sourceDataType, 4, sourceAddress, sourceProgram);
		setData(destinationDataType1, 2, destinationAddress, destinationProgram);

		VTMatch match = createMatchSetWithOneDataMatch(session, sourceAddress, destinationAddress);

		// data type choice
		controller.getOptions().setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
			ReplaceDataChoices.REPLACE_ALL_DATA);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		VTAssociationStatus status = match.getAssociation().getStatus();
		assertEquals(VTAssociationStatus.ACCEPTED, status);
		checkDataMatchDataType(sourceDataType, 4, destinationAddress, destinationListing);

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);

		status = match.getAssociation().getStatus();
		assertEquals(VTAssociationStatus.AVAILABLE, status);
		checkDataMatchDataType(destinationDataType1, 2, destinationAddress, destinationListing);
		checkDataMatchDataType(DataType.DEFAULT, 1, destinationAddress.add(2), destinationListing);
	}

	@Test
	public void testApplyMatchFunctionNames_Ignore() throws Exception {

		Address sourceAddress = addr("0x01003f9e", sourceProgram);
		Address destinationAddress = addr("0x01003f9e", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		setFunctionName("Foo", sourceAddress, sourceProgram);
		assertEquals("Foo", sourceFunction.getName());
		assertEquals("FUN_01003f9e", destinationFunction.getName());

		// function name choices
		controller.getOptions().setEnum(VTOptionDefines.FUNCTION_NAME, FunctionNameChoices.EXCLUDE);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		assertEquals("Foo", sourceFunction.getName());
		assertEquals("FUN_01003f9e", destinationFunction.getName());
	}

	@Test
	public void testApplyMatchFunctionNames_ReplaceDefault_Default() throws Exception {

		Address sourceAddress = addr("0x01003f9e", sourceProgram);
		Address destinationAddress = addr("0x01003f9e", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		setFunctionName("Foo", sourceAddress, sourceProgram);
		assertEquals("Foo", sourceFunction.getName());
		assertEquals("FUN_01003f9e", destinationFunction.getName());

		// function name choices
		controller.getOptions().setEnum(VTOptionDefines.FUNCTION_NAME,
			FunctionNameChoices.REPLACE_DEFAULT_ONLY);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		assertEquals("Foo", sourceFunction.getName());
		assertEquals("Foo", destinationFunction.getName());

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);
		assertEquals("Foo", sourceFunction.getName());
		assertEquals("FUN_01003f9e", destinationFunction.getName());
	}

	@Test
	public void testApplyMatchFunctionNames_ReplaceDefault_UserDefined() throws Exception {

		Address sourceAddress = addr("0x01003f9e", sourceProgram);
		Address destinationAddress = addr("0x01003f9e", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		setFunctionName("Foo", sourceAddress, sourceProgram);
		setFunctionName("Bar", destinationAddress, destinationProgram);
		assertEquals("Foo", sourceFunction.getName());
		assertEquals("Bar", destinationFunction.getName());

		// function name choices
		controller.getOptions().setEnum(VTOptionDefines.FUNCTION_NAME,
			FunctionNameChoices.REPLACE_DEFAULT_ONLY);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		assertEquals("Foo", sourceFunction.getName());
		assertEquals("Bar", destinationFunction.getName());
	}

	@Test
	public void testApplyMatchFunctionNames_ReplaceAlways_Default() throws Exception {

		Address sourceAddress = addr("0x01003f9e", sourceProgram);
		Address destinationAddress = addr("0x01003f9e", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		setFunctionName("Foo", sourceAddress, sourceProgram);
		assertEquals("Foo", sourceFunction.getName());
		assertEquals("FUN_01003f9e", destinationFunction.getName());

		// function name choices
		controller.getOptions().setEnum(VTOptionDefines.FUNCTION_NAME,
			FunctionNameChoices.REPLACE_ALWAYS);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		assertEquals("Foo", sourceFunction.getName());
		assertEquals("Foo", destinationFunction.getName());

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);
		assertEquals("Foo", sourceFunction.getName());
		assertEquals("FUN_01003f9e", destinationFunction.getName());
	}

	@Test
	public void testApplyMatchFunctionNames_ReplaceAlways_UserDefined() throws Exception {

		Address sourceAddress = addr("0x01003f9e", sourceProgram);
		Address destinationAddress = addr("0x01003f9e", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		setFunctionName("Foo", sourceAddress, sourceProgram);
		setFunctionName("Bar", destinationAddress, destinationProgram);
		assertEquals("Foo", sourceFunction.getName());
		assertEquals("Bar", destinationFunction.getName());

		// function name choices
		controller.getOptions().setEnum(VTOptionDefines.FUNCTION_NAME,
			FunctionNameChoices.REPLACE_ALWAYS);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		assertEquals("Foo", sourceFunction.getName());
		assertEquals("Foo", destinationFunction.getName());

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);
		assertEquals("Foo", sourceFunction.getName());
		assertEquals("Bar", destinationFunction.getName());
	}

	@Test
	public void testApplyMatchFunctionNames_Add_Default() throws Exception {

		Address sourceAddress = addr("0x01003f9e", sourceProgram);
		Address destinationAddress = addr("0x01003f9e", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		setFunctionName("Foo", sourceAddress, sourceProgram);
		assertEquals("Foo", sourceFunction.getName());
		assertEquals("FUN_01003f9e", destinationFunction.getName());
		assertNull(getGlobalDestinationSymbol("Foo", destinationAddress));

		// function name choices
		controller.getOptions().setEnum(VTOptionDefines.FUNCTION_NAME, FunctionNameChoices.ADD);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		assertEquals("Foo", sourceFunction.getName());
		assertEquals("Foo", destinationFunction.getName());

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);
		assertEquals("Foo", sourceFunction.getName());
		assertEquals("FUN_01003f9e", destinationFunction.getName());
		assertNull(getGlobalDestinationSymbol("Foo", destinationAddress));
	}

	private Symbol getGlobalDestinationSymbol(String name, Address destinationAddress) {
		return destinationProgram.getSymbolTable().getGlobalSymbol(name, destinationAddress);
	}

	@Test
	public void testApplyMatchFunctionNames_Add_UserDefined() throws Exception {

		Address sourceAddress = addr("0x01003f9e", sourceProgram);
		Address destinationAddress = addr("0x01003f9e", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		setFunctionName("Foo", sourceAddress, sourceProgram);
		setFunctionName("Bar", destinationAddress, destinationProgram);
		assertEquals("Foo", sourceFunction.getName());
		assertEquals("Bar", destinationFunction.getName());
		assertNull(getGlobalDestinationSymbol("Foo", destinationAddress));

		// function name choices
		controller.getOptions().setEnum(VTOptionDefines.FUNCTION_NAME, FunctionNameChoices.ADD);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		assertEquals("Foo", sourceFunction.getName());
		assertEquals("Bar", destinationFunction.getName());
		assertNotNull(getGlobalDestinationSymbol("Foo", destinationAddress));

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);
		assertEquals("Foo", sourceFunction.getName());
		assertEquals("Bar", destinationFunction.getName());
		assertNull(getGlobalDestinationSymbol("Foo", destinationAddress));
	}

	@Test
	public void testApplyWithSomeMarkupItemsAlreadyApplied() throws Exception {

		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		Address destinationAddress = addr("0x01002cf5", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Address labelAddress = addr("0x01002d06", sourceProgram);
		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);
		Symbol destinationSymbol1 = addLabel(labelAddress, destinationProgram);

		// symbol/comment choices
		ToolOptions options = controller.getOptions();
		options.setEnum(VTOptionDefines.LABELS, LabelChoices.REPLACE_ALL);
		options.setEnum(VTOptionDefines.END_OF_LINE_COMMENT, CommentChoices.APPEND_TO_EXISTING);

		// symbol/comment choices
		String sourceComment = "Hi mom replace";
		String destinationComment = "Hi dad replace";
		Address commentAddress = addr("0x01002d06", sourceProgram);
		setComment(sourceProgram, commentAddress, CodeUnit.EOL_COMMENT, sourceComment);
		setComment(destinationProgram, commentAddress, CodeUnit.EOL_COMMENT, destinationComment);

		MatchInfo matchInfo = controller.getMatchInfo(match);
		Collection<VTMarkupItem> markupItems =
			matchInfo.getAppliableMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR);

		List<VTMarkupItem> itemsToApply = new ArrayList<>();
		for (VTMarkupItem item : markupItems) {
			Address itemSourceAddress = item.getSourceAddress();
			if (commentAddress.equals(itemSourceAddress) &&
				(item.getMarkupType() instanceof CommentMarkupType)) {
				itemsToApply.add(item);
				break;
			}
		}

		//
		// Apply only one item now (our comment item)
		//
		ApplyMarkupItemTask markupTask =
			new ApplyMarkupItemTask(controller.getSession(), itemsToApply, options);
		runTask(markupTask);

		String expectedComment = destinationComment + "\n" + sourceComment;
		Listing destinationListing = destinationProgram.getListing();
		String comment = destinationListing.getComment(CodeUnit.EOL_COMMENT, commentAddress);
		assertEquals("Comment was not applied", expectedComment, comment);

		//
		// Now call the match apply task and make sure the remaining item is applied
		//
		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		// make sure these symbols are still applied (from earlier)
		Symbol expectedSymbol = sourceSymbol1;
		SymbolTable symbolTable = destinationProgram.getSymbolTable();
		Symbol[] newSymbols = symbolTable.getSymbols(labelAddress);
		Symbol[] expectedSymbols = new Symbol[] { expectedSymbol };
		assertTrue("New symbol does not match the source symbol",
			SystemUtilities.isArrayEqual(expectedSymbols, newSymbols));

		expectedComment = destinationComment + "\n" + sourceComment;
		destinationListing = destinationProgram.getListing();
		comment = destinationListing.getComment(CodeUnit.EOL_COMMENT, commentAddress);
		assertEquals("Comment was not applied", expectedComment, comment);

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);
		newSymbols = symbolTable.getSymbols(labelAddress);
		expectedSymbols = new Symbol[] { destinationSymbol1 };
		assertTrue("New symbol does not match the source symbol",
			SystemUtilities.isArrayEqual(expectedSymbols, newSymbols));

		comment = destinationListing.getComment(CodeUnit.EOL_COMMENT, commentAddress);
		assertEquals("Comment was not unpplied", destinationComment, comment);
	}

	@Test
	public void testApplyMatchReturnType_Ignore() throws Exception {

		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		Address destinationAddress = addr("0x01002cf5", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		PointerDataType bytePointer = new PointerDataType(new ByteDataType());
		setReturnType(bytePointer, sourceAddress, sourceProgram);
		setReturnType(dWordDataType, destinationAddress, destinationProgram);
		checkReturnType(bytePointer, sourceFunction);
		checkReturnType(dWordDataType, destinationFunction);

		// function name choices
		controller.getOptions().setEnum(VTOptionDefines.FUNCTION_SIGNATURE,
			FunctionSignatureChoices.EXCLUDE);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		checkReturnType(bytePointer, sourceFunction);
		checkReturnType(dWordDataType, destinationFunction);
	}

	@Test
	public void testApplyMatchReturnType_Replace() throws Exception {

		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		Address destinationAddress = addr("0x01002cf5", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		PointerDataType bytePointer = new PointerDataType(new ByteDataType());
		setReturnType(bytePointer, sourceAddress, sourceProgram);
		setReturnType(dWordDataType, destinationAddress, destinationProgram);
		checkReturnType(bytePointer, sourceFunction);
		checkReturnType(dWordDataType, destinationFunction);

		// function name choices
		controller.getOptions().setEnum(VTOptionDefines.FUNCTION_SIGNATURE,
			FunctionSignatureChoices.REPLACE);
		controller.getOptions().setEnum(VTOptionDefines.FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		checkReturnType(bytePointer, sourceFunction);
		checkReturnType(bytePointer, destinationFunction);

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);
		checkReturnType(bytePointer, sourceFunction);
		checkReturnType(dWordDataType, destinationFunction);
	}

	@Test
	public void testApplyMatchParameterNameDataTypeComment_Ignore() throws Exception {

		Address sourceAddress = addr("0x0100415a", sourceProgram);
		Address destinationAddress = addr("0x0100415a", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);

		setupParameters(sourceFunction, destinationFunction);

		// function name choices
		controller.getOptions().setEnum(VTOptionDefines.FUNCTION_SIGNATURE,
			FunctionSignatureChoices.EXCLUDE);
		controller.getOptions().setEnum(VTOptionDefines.PARAMETER_NAMES,
			SourcePriorityChoices.EXCLUDE);
		controller.getOptions().setEnum(VTOptionDefines.PARAMETER_COMMENTS, CommentChoices.EXCLUDE);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		Parameter[] sourceParameters = sourceFunction.getParameters();
		Parameter[] destinationParameters = destinationFunction.getParameters();
		assertEquals(3, sourceParameters.length);
		assertEquals(3, destinationParameters.length);

		// Verify the source parameters.
		checkParameterDataType(sourceParameters[0], stringPointerDataType);
		checkParameterDataType(sourceParameters[1], dWordDataType);
		checkParameterDataType(sourceParameters[2], floatDataType);
		checkParameterName(sourceParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[1], "value", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[2], "percentage", SourceType.USER_DEFINED);
		checkParameterComment(sourceParameters[0], "This is the first parameter.");
		checkParameterComment(sourceParameters[1], "This is the second parameter.");
		checkParameterComment(sourceParameters[2], "This is the third parameter.");

		// Verify the destination parameters.
		checkParameterDataType(destinationParameters[0], undefined4DataType);
		checkParameterDataType(destinationParameters[1], undefined4DataType);
		checkParameterDataType(destinationParameters[2], undefined4DataType);
		checkParameterName(destinationParameters[0], "param_1", SourceType.DEFAULT);
		checkParameterName(destinationParameters[1], "apple", SourceType.IMPORTED);
		checkParameterName(destinationParameters[2], "orange", SourceType.USER_DEFINED);
		checkParameterComment(destinationParameters[0], "Once upon a time...");
		checkParameterComment(destinationParameters[1], null);
		checkParameterComment(destinationParameters[2], null);
	}

	@Test
	public void testApplyMatchParameterDataType_Replace() throws Exception {

		Address sourceAddress = addr("0x0100415a", sourceProgram);
		Address destinationAddress = addr("0x0100415a", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);

		setupParameters(sourceFunction, destinationFunction);

		// function name choices
		controller.getOptions().setEnum(VTOptionDefines.FUNCTION_SIGNATURE,
			FunctionSignatureChoices.REPLACE);
		controller.getOptions().setEnum(VTOptionDefines.FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE);
		controller.getOptions().setEnum(VTOptionDefines.PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE);
		controller.getOptions().setEnum(VTOptionDefines.PARAMETER_NAMES,
			SourcePriorityChoices.EXCLUDE);
		controller.getOptions().setEnum(VTOptionDefines.PARAMETER_COMMENTS, CommentChoices.EXCLUDE);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		Parameter[] sourceParameters = sourceFunction.getParameters();
		Parameter[] destinationParameters = destinationFunction.getParameters();
		assertEquals(3, sourceParameters.length);
		assertEquals(3, destinationParameters.length);

		checkParameterDataType(sourceParameters[0], stringPointerDataType);
		checkParameterDataType(sourceParameters[1], dWordDataType);
		checkParameterDataType(sourceParameters[2], floatDataType);
		checkParameterName(sourceParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[1], "value", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[2], "percentage", SourceType.USER_DEFINED);
		checkParameterComment(sourceParameters[0], "This is the first parameter.");
		checkParameterComment(sourceParameters[1], "This is the second parameter.");
		checkParameterComment(sourceParameters[2], "This is the third parameter.");

		checkParameterDataType(destinationParameters[0], stringPointerDataType);
		checkParameterDataType(destinationParameters[1], dWordDataType);
		checkParameterDataType(destinationParameters[2], floatDataType);
		checkParameterName(destinationParameters[0], "param_1", SourceType.DEFAULT);
		checkParameterName(destinationParameters[1], "apple", SourceType.IMPORTED);
		checkParameterName(destinationParameters[2], "orange", SourceType.USER_DEFINED);
		checkParameterComment(destinationParameters[0], "Once upon a time...");
		checkParameterComment(destinationParameters[1], null);
		checkParameterComment(destinationParameters[2], null);

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);

		sourceParameters = sourceFunction.getParameters();
		destinationParameters = destinationFunction.getParameters();
		assertEquals(3, sourceParameters.length);
		assertEquals(3, destinationParameters.length);

		checkParameterDataType(sourceParameters[0], stringPointerDataType);
		checkParameterDataType(sourceParameters[1], dWordDataType);
		checkParameterDataType(sourceParameters[2], floatDataType);
		checkParameterName(sourceParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[1], "value", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[2], "percentage", SourceType.USER_DEFINED);
		checkParameterComment(sourceParameters[0], "This is the first parameter.");
		checkParameterComment(sourceParameters[1], "This is the second parameter.");
		checkParameterComment(sourceParameters[2], "This is the third parameter.");

		checkParameterDataType(destinationParameters[0], undefined4DataType);
		checkParameterDataType(destinationParameters[1], undefined4DataType);
		checkParameterDataType(destinationParameters[2], undefined4DataType);
		checkParameterName(destinationParameters[0], "param_1", SourceType.DEFAULT);
		checkParameterName(destinationParameters[1], "apple", SourceType.IMPORTED);
		checkParameterName(destinationParameters[2], "orange", SourceType.USER_DEFINED);
		checkParameterComment(destinationParameters[0], "Once upon a time...");
		checkParameterComment(destinationParameters[1], null);
		checkParameterComment(destinationParameters[2], null);
	}

	@Test
	public void testApplyMatchParameterName_ReplaceDefault() throws Exception {

		Address sourceAddress = addr("0x0100415a", sourceProgram);
		Address destinationAddress = addr("0x0100415a", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);

		setupParameters(sourceFunction, destinationFunction);

		// function name choices
		ToolOptions options = controller.getOptions();
		options.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		options.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		options.setEnum(INLINE, ReplaceChoices.REPLACE);
		options.setEnum(NO_RETURN, ReplaceChoices.REPLACE);
		options.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.EXCLUDE);
		options.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.EXCLUDE);
		options.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);
//		options.putBoolean(PARAMETER_NAMES_ONLY_REPLACE_DEFAULTS, true);
//		options.putBoolean(PARAMETER_NAMES_DO_NOT_REPLACE_WITH_DEFAULTS, false);
		options.setEnum(PARAMETER_COMMENTS, CommentChoices.EXCLUDE);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		Parameter[] sourceParameters = sourceFunction.getParameters();
		Parameter[] destinationParameters = destinationFunction.getParameters();
		assertEquals(3, sourceParameters.length);
		assertEquals(3, destinationParameters.length);

		checkParameterDataType(sourceParameters[0], stringPointerDataType);
		checkParameterDataType(sourceParameters[1], dWordDataType);
		checkParameterDataType(sourceParameters[2], floatDataType);
		checkParameterName(sourceParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[1], "value", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[2], "percentage", SourceType.USER_DEFINED);
		checkParameterComment(sourceParameters[0], "This is the first parameter.");
		checkParameterComment(sourceParameters[1], "This is the second parameter.");
		checkParameterComment(sourceParameters[2], "This is the third parameter.");

		checkParameterDataType(destinationParameters[0], undefined4DataType);
		checkParameterDataType(destinationParameters[1], undefined4DataType);
		checkParameterDataType(destinationParameters[2], undefined4DataType);
		checkParameterName(destinationParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(destinationParameters[1], "apple", SourceType.IMPORTED);
		checkParameterName(destinationParameters[2], "orange", SourceType.USER_DEFINED);
		checkParameterComment(destinationParameters[0], "Once upon a time...");
		checkParameterComment(destinationParameters[1], null);
		checkParameterComment(destinationParameters[2], null);

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);

		sourceParameters = sourceFunction.getParameters();
		destinationParameters = destinationFunction.getParameters();
		assertEquals(3, sourceParameters.length);
		assertEquals(3, destinationParameters.length);

		checkParameterDataType(sourceParameters[0], stringPointerDataType);
		checkParameterDataType(sourceParameters[1], dWordDataType);
		checkParameterDataType(sourceParameters[2], floatDataType);
		checkParameterName(sourceParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[1], "value", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[2], "percentage", SourceType.USER_DEFINED);
		checkParameterComment(sourceParameters[0], "This is the first parameter.");
		checkParameterComment(sourceParameters[1], "This is the second parameter.");
		checkParameterComment(sourceParameters[2], "This is the third parameter.");

		checkParameterDataType(destinationParameters[0], undefined4DataType);
		checkParameterDataType(destinationParameters[1], undefined4DataType);
		checkParameterDataType(destinationParameters[2], undefined4DataType);
		checkParameterName(destinationParameters[0], "param_1", SourceType.DEFAULT);
		checkParameterName(destinationParameters[1], "apple", SourceType.IMPORTED);
		checkParameterName(destinationParameters[2], "orange", SourceType.USER_DEFINED);
		checkParameterComment(destinationParameters[0], "Once upon a time...");
		checkParameterComment(destinationParameters[1], null);
		checkParameterComment(destinationParameters[2], null);
	}

	@Test
	public void testApplyMatchParameterName_ReplaceAlways() throws Exception {

		Address sourceAddress = addr("0x0100415a", sourceProgram);
		Address destinationAddress = addr("0x0100415a", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);

		setupParameters(sourceFunction, destinationFunction);

		// function parameter name/comment choices
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
//		applyOptions.putBoolean(PARAMETER_NAMES_DO_NOT_REPLACE_WITH_DEFAULTS, false);
//		applyOptions.putBoolean(PARAMETER_NAMES_ONLY_REPLACE_DEFAULTS, false);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.EXCLUDE);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		Parameter[] sourceParameters = sourceFunction.getParameters();
		Parameter[] destinationParameters = destinationFunction.getParameters();
		assertEquals(3, sourceParameters.length);
		assertEquals(3, destinationParameters.length);

		checkParameterDataType(sourceParameters[0], stringPointerDataType);
		checkParameterDataType(sourceParameters[1], dWordDataType);
		checkParameterDataType(sourceParameters[2], floatDataType);
		checkParameterName(sourceParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[1], "value", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[2], "percentage", SourceType.USER_DEFINED);
		checkParameterComment(sourceParameters[0], "This is the first parameter.");
		checkParameterComment(sourceParameters[1], "This is the second parameter.");
		checkParameterComment(sourceParameters[2], "This is the third parameter.");

		checkParameterDataType(destinationParameters[0], undefined4DataType);
		checkParameterDataType(destinationParameters[1], undefined4DataType);
		checkParameterDataType(destinationParameters[2], undefined4DataType);
		checkParameterName(destinationParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(destinationParameters[1], "value", SourceType.USER_DEFINED);
		checkParameterName(destinationParameters[2], "percentage", SourceType.USER_DEFINED);
		checkParameterComment(destinationParameters[0], "Once upon a time...");
		checkParameterComment(destinationParameters[1], null);
		checkParameterComment(destinationParameters[2], null);

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);

		sourceParameters = sourceFunction.getParameters();
		destinationParameters = destinationFunction.getParameters();
		assertEquals(3, sourceParameters.length);
		assertEquals(3, destinationParameters.length);

		checkParameterDataType(sourceParameters[0], stringPointerDataType);
		checkParameterDataType(sourceParameters[1], dWordDataType);
		checkParameterDataType(sourceParameters[2], floatDataType);
		checkParameterName(sourceParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[1], "value", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[2], "percentage", SourceType.USER_DEFINED);
		checkParameterComment(sourceParameters[0], "This is the first parameter.");
		checkParameterComment(sourceParameters[1], "This is the second parameter.");
		checkParameterComment(sourceParameters[2], "This is the third parameter.");

		checkParameterDataType(destinationParameters[0], undefined4DataType);
		checkParameterDataType(destinationParameters[1], undefined4DataType);
		checkParameterDataType(destinationParameters[2], undefined4DataType);
		checkParameterName(destinationParameters[0], "param_1", SourceType.DEFAULT);
		checkParameterName(destinationParameters[1], "apple", SourceType.IMPORTED);
		checkParameterName(destinationParameters[2], "orange", SourceType.USER_DEFINED);
		checkParameterComment(destinationParameters[0], "Once upon a time...");
		checkParameterComment(destinationParameters[1], null);
		checkParameterComment(destinationParameters[2], null);
	}

	@Test
	public void testApplyMatchParameterComment_Overwrite() throws Exception {

		Address sourceAddress = addr("0x0100415a", sourceProgram);
		Address destinationAddress = addr("0x0100415a", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);

		setupParameters(sourceFunction, destinationFunction);

		// function parameter name/comment choices
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);
//		applyOptions.putBoolean(PARAMETER_NAMES_DO_NOT_REPLACE_WITH_DEFAULTS, true);
//		applyOptions.putBoolean(PARAMETER_NAMES_ONLY_REPLACE_DEFAULTS, true);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.OVERWRITE_EXISTING);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		Parameter[] sourceParameters = sourceFunction.getParameters();
		Parameter[] destinationParameters = destinationFunction.getParameters();
		assertEquals(3, sourceParameters.length);
		assertEquals(3, destinationParameters.length);

		checkParameterDataType(sourceParameters[0], stringPointerDataType);
		checkParameterDataType(sourceParameters[1], dWordDataType);
		checkParameterDataType(sourceParameters[2], floatDataType);
		checkParameterName(sourceParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[1], "value", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[2], "percentage", SourceType.USER_DEFINED);
		checkParameterComment(sourceParameters[0], "This is the first parameter.");
		checkParameterComment(sourceParameters[1], "This is the second parameter.");
		checkParameterComment(sourceParameters[2], "This is the third parameter.");

		checkParameterDataType(destinationParameters[0], undefined4DataType);
		checkParameterDataType(destinationParameters[1], undefined4DataType);
		checkParameterDataType(destinationParameters[2], undefined4DataType);
		checkParameterName(destinationParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(destinationParameters[1], "apple", SourceType.IMPORTED);
		checkParameterName(destinationParameters[2], "orange", SourceType.USER_DEFINED);
		checkParameterComment(destinationParameters[0], "This is the first parameter.");
		checkParameterComment(destinationParameters[1], "This is the second parameter.");
		checkParameterComment(destinationParameters[2], "This is the third parameter.");

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);

		sourceParameters = sourceFunction.getParameters();
		destinationParameters = destinationFunction.getParameters();
		assertEquals(3, sourceParameters.length);
		assertEquals(3, destinationParameters.length);

		checkParameterDataType(sourceParameters[0], stringPointerDataType);
		checkParameterDataType(sourceParameters[1], dWordDataType);
		checkParameterDataType(sourceParameters[2], floatDataType);
		checkParameterName(sourceParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[1], "value", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[2], "percentage", SourceType.USER_DEFINED);
		checkParameterComment(sourceParameters[0], "This is the first parameter.");
		checkParameterComment(sourceParameters[1], "This is the second parameter.");
		checkParameterComment(sourceParameters[2], "This is the third parameter.");

		checkParameterDataType(destinationParameters[0], undefined4DataType);
		checkParameterDataType(destinationParameters[1], undefined4DataType);
		checkParameterDataType(destinationParameters[2], undefined4DataType);
		checkParameterName(destinationParameters[0], "param_1", SourceType.DEFAULT);
		checkParameterName(destinationParameters[1], "apple", SourceType.IMPORTED);
		checkParameterName(destinationParameters[2], "orange", SourceType.USER_DEFINED);
		checkParameterComment(destinationParameters[0], "Once upon a time...");
		checkParameterComment(destinationParameters[1], null);
		checkParameterComment(destinationParameters[2], null);
	}

	@Test
	public void testApplyMatchParameterComment_Append() throws Exception {

		Address sourceAddress = addr("0x0100415a", sourceProgram);
		Address destinationAddress = addr("0x0100415a", destinationProgram);

		VTMatch match = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		// force known values for the test
		Function sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);

		setupParameters(sourceFunction, destinationFunction);

		// function parameter name/comment choices
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);
//		applyOptions.putBoolean(PARAMETER_NAMES_DO_NOT_REPLACE_WITH_DEFAULTS, false);
//		applyOptions.putBoolean(PARAMETER_NAMES_ONLY_REPLACE_DEFAULTS, true);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);

		Parameter[] sourceParameters = sourceFunction.getParameters();
		Parameter[] destinationParameters = destinationFunction.getParameters();
		assertEquals(3, sourceParameters.length);
		assertEquals(3, destinationParameters.length);

		checkParameterDataType(sourceParameters[0], stringPointerDataType);
		checkParameterDataType(sourceParameters[1], dWordDataType);
		checkParameterDataType(sourceParameters[2], floatDataType);
		checkParameterName(sourceParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[1], "value", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[2], "percentage", SourceType.USER_DEFINED);
		checkParameterComment(sourceParameters[0], "This is the first parameter.");
		checkParameterComment(sourceParameters[1], "This is the second parameter.");
		checkParameterComment(sourceParameters[2], "This is the third parameter.");

		checkParameterDataType(destinationParameters[0], undefined4DataType);
		checkParameterDataType(destinationParameters[1], undefined4DataType);
		checkParameterDataType(destinationParameters[2], undefined4DataType);
		checkParameterName(destinationParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(destinationParameters[1], "apple", SourceType.IMPORTED);
		checkParameterName(destinationParameters[2], "orange", SourceType.USER_DEFINED);
		checkParameterComment(destinationParameters[0],
			"Once upon a time...\nThis is the first parameter.");
		checkParameterComment(destinationParameters[1], "This is the second parameter.");
		checkParameterComment(destinationParameters[2], "This is the third parameter.");

		//
		// Now test the unapply
		//
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(unapplyTask);

		sourceParameters = sourceFunction.getParameters();
		destinationParameters = destinationFunction.getParameters();
		assertEquals(3, sourceParameters.length);
		assertEquals(3, destinationParameters.length);

		checkParameterDataType(sourceParameters[0], stringPointerDataType);
		checkParameterDataType(sourceParameters[1], dWordDataType);
		checkParameterDataType(sourceParameters[2], floatDataType);
		checkParameterName(sourceParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[1], "value", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[2], "percentage", SourceType.USER_DEFINED);
		checkParameterComment(sourceParameters[0], "This is the first parameter.");
		checkParameterComment(sourceParameters[1], "This is the second parameter.");
		checkParameterComment(sourceParameters[2], "This is the third parameter.");

		checkParameterDataType(destinationParameters[0], undefined4DataType);
		checkParameterDataType(destinationParameters[1], undefined4DataType);
		checkParameterDataType(destinationParameters[2], undefined4DataType);
		checkParameterName(destinationParameters[0], "param_1", SourceType.DEFAULT);
		checkParameterName(destinationParameters[1], "apple", SourceType.IMPORTED);
		checkParameterName(destinationParameters[2], "orange", SourceType.USER_DEFINED);
		checkParameterComment(destinationParameters[0], "Once upon a time...");
		checkParameterComment(destinationParameters[1], null);
		checkParameterComment(destinationParameters[2], null);
	}

	@Test
	public void testApplyBlockedMatch() throws Exception {

		env.showTool();

		Address sourceAddress1 = addr("0x01002cf5", sourceProgram);
		Address destinationAddress1 = addr("0x01002cf5", destinationProgram);

		Address sourceAddress2 = addr("0x010048a3", sourceProgram);
		Address destinationAddress2 = addr("0x010048a3", destinationProgram);

		Address sourceAddress3 = addr("0x01002cf5", sourceProgram);
		Address destinationAddress3 = addr("0x010048a3", destinationProgram);

		List<AssociationPair> associations = new ArrayList<>();
		associations.add(new AssociationPair(sourceAddress1, destinationAddress1));
		associations.add(new AssociationPair(sourceAddress2, destinationAddress2));
		associations.add(new AssociationPair(sourceAddress3, destinationAddress3));

		VTMatchSet matchSet = createMatchSetFromList(session, associations);

		// force known values for the test
		VTMatch matchToApply = getMatch(matchSet, sourceAddress3, destinationAddress3);
		applyMatch(matchToApply);

		VTMatch match3 = getMatch(matchSet, sourceAddress3, destinationAddress3);
		assertEquals(VTAssociationStatus.ACCEPTED, match3.getAssociation().getStatus());
		VTMatch match1 = getMatch(matchSet, sourceAddress1, destinationAddress1);
		assertEquals(VTAssociationStatus.BLOCKED, match1.getAssociation().getStatus());
		VTMatch match2 = getMatch(matchSet, sourceAddress2, destinationAddress2);
		assertEquals(VTAssociationStatus.BLOCKED, match2.getAssociation().getStatus());

		final List<VTMatch> selectedMatches = new ArrayList<>();
		selectedMatches.add(match1);

		runSwing(() -> {
			VTMatchTableProvider matchTableProvider =
				(VTMatchTableProvider) getInstanceField("matchesProvider", plugin);
			assertNotNull(matchTableProvider);
			ActionContext matchContext =
				new VTMatchContext(matchTableProvider, selectedMatches, session);
			ApplyBlockedMatchAction applyBlockedMatchAction =
				new ApplyBlockedMatchAction(controller);
			applyBlockedMatchAction.actionPerformed(matchContext);
		}, false);

		Window dialog = waitForWindow("Clear Conflicting Matches and Apply?");
		assertNotNull(dialog);
		pressButtonByText(dialog, "Clear and Apply");
		waitForBusyTool(tool);

		match3 = getMatch(matchSet, sourceAddress3, destinationAddress3);
		assertEquals(VTAssociationStatus.BLOCKED, match3.getAssociation().getStatus());
		match1 = getMatch(matchSet, sourceAddress1, destinationAddress1);
		assertEquals(VTAssociationStatus.ACCEPTED, match1.getAssociation().getStatus());
		match2 = getMatch(matchSet, sourceAddress2, destinationAddress2);
		assertEquals(VTAssociationStatus.AVAILABLE, match2.getAssociation().getStatus());

	}

	@Test
	public void testApplyBlockedMatchButCancel() throws Exception {

		env.showTool();

		Address sourceAddress1 = addr("0x01002cf5", sourceProgram);
		Address destinationAddress1 = addr("0x01002cf5", destinationProgram);

		Address sourceAddress2 = addr("0x010048a3", sourceProgram);
		Address destinationAddress2 = addr("0x010048a3", destinationProgram);

		Address sourceAddress3 = addr("0x01002cf5", sourceProgram);
		Address destinationAddress3 = addr("0x010048a3", destinationProgram);

		List<AssociationPair> associations = new ArrayList<>();
		associations.add(new AssociationPair(sourceAddress1, destinationAddress1));
		associations.add(new AssociationPair(sourceAddress2, destinationAddress2));
		associations.add(new AssociationPair(sourceAddress3, destinationAddress3));

		VTMatchSet matchSet = createMatchSetFromList(session, associations);

		// force known values for the test
		VTMatch matchToApply = getMatch(matchSet, sourceAddress3, destinationAddress3);
		applyMatch(matchToApply);

		VTMatch match3 = getMatch(matchSet, sourceAddress3, destinationAddress3);
		assertEquals(VTAssociationStatus.ACCEPTED, match3.getAssociation().getStatus());
		VTMatch match1 = getMatch(matchSet, sourceAddress1, destinationAddress1);
		assertEquals(VTAssociationStatus.BLOCKED, match1.getAssociation().getStatus());
		VTMatch match2 = getMatch(matchSet, sourceAddress2, destinationAddress2);
		assertEquals(VTAssociationStatus.BLOCKED, match2.getAssociation().getStatus());

		final List<VTMatch> selectedMatches = new ArrayList<>();
		selectedMatches.add(match1);

		runSwing(() -> {
			VTMatchTableProvider matchTableProvider =
				(VTMatchTableProvider) getInstanceField("matchesProvider", plugin);
			assertNotNull(matchTableProvider);
			ActionContext matchContext =
				new VTMatchContext(matchTableProvider, selectedMatches, session);
			ApplyBlockedMatchAction applyBlockedMatchAction =
				new ApplyBlockedMatchAction(controller);
			applyBlockedMatchAction.actionPerformed(matchContext);
		}, false);

		Window dialog = waitForWindow("Clear Conflicting Matches and Apply?");
		assertNotNull(dialog);
		pressButtonByText(dialog, "Cancel");
		waitForSwing();

		match3 = getMatch(matchSet, sourceAddress3, destinationAddress3);
		assertEquals(VTAssociationStatus.ACCEPTED, match3.getAssociation().getStatus());
		match1 = getMatch(matchSet, sourceAddress1, destinationAddress1);
		assertEquals(VTAssociationStatus.BLOCKED, match1.getAssociation().getStatus());
		match2 = getMatch(matchSet, sourceAddress2, destinationAddress2);
		assertEquals(VTAssociationStatus.BLOCKED, match2.getAssociation().getStatus());

	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void runTask(Task task) {
		int id = session.startTransaction("Test");
		try {
			task.run(TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			fail("Can't happen while using a dummy");
		}
		finally {
			session.endTransaction(id, true);
		}
		destinationProgram.flushEvents();
		waitForSwing();
	}

	private Symbol addLabel(Address address, Program program) throws InvalidInputException {
		return addLabel("test" + getNonDynamicRandomString(), address, program);
	}

	protected String getNonDynamicRandomString() {
		return getRandomString().replaceAll("_", "");
	}

	private void checkDataMatchDataType(DataType expectedDataType, int expectedLength,
			Address address, Listing listing) {
		Data data = listing.getDataAt(address);
		assertNotNull(data);
		DataType dataType = data.getDataType();
		assertTrue("Expected data type '" + expectedDataType.toString() + "', but was '" +
			dataType.toString() + "'.", expectedDataType.isEquivalent(dataType));
	}

	private Data setData(DataType dataType, int dtLength, Address address, Program program)
			throws CodeUnitInsertionException, DataTypeConflictException {

		Listing listing = program.getListing();
		Data data = null;
		boolean commit = false;
		int transaction = program.startTransaction("Test - Set Data");
		try {
			data = listing.createData(address, dataType, dtLength);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		return data;
	}

	private Function setFunctionName(String name, Address address, Program program)
			throws DuplicateNameException, InvalidInputException {

		Function function = program.getFunctionManager().getFunctionAt(address);
		if (function == null) {
			return null;
		}
		boolean commit = false;
		int transaction = program.startTransaction("Test - Set Function Name");
		try {
			function.setName(name, SourceType.USER_DEFINED);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		return function;
	}

	private Function setReturnType(DataType returnType, Address address, Program program)
			throws InvalidInputException {

		Function function = program.getFunctionManager().getFunctionAt(address);
		if (function == null) {
			return null;
		}
		boolean commit = false;
		int transaction = program.startTransaction("Test - Set Return Type");
		try {
			function.setReturnType(returnType, SourceType.ANALYSIS);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		return function;
	}

	private void checkReturnType(DataType expectedReturnType, Function function) {
		DataType functionReturnType = function.getReturnType();
		assertTrue("Expected " + expectedReturnType + ", but was " + functionReturnType,
			expectedReturnType.isEquivalent(functionReturnType));
	}

	private void setupParameters(Function sourceFunction, Function destinationFunction)
			throws InvalidInputException, DuplicateNameException {

		Parameter[] sourceParameters = sourceFunction.getParameters();
		Parameter[] destinationParameters = destinationFunction.getParameters();
		assertEquals(3, sourceParameters.length);
		assertEquals(3, destinationParameters.length);

		// Setup the source parameters as desired.
		setParameterDataType(sourceParameters[0], stringPointerDataType);
		setParameterDataType(sourceParameters[1], dWordDataType);
		setParameterDataType(sourceParameters[2], floatDataType);
		setParameterName(sourceParameters[0], "destination", SourceType.USER_DEFINED);
		setParameterName(sourceParameters[1], "value", SourceType.USER_DEFINED);
		setParameterName(sourceParameters[2], "percentage", SourceType.USER_DEFINED);
		setParameterComment(sourceParameters[0], "This is the first parameter.");
		setParameterComment(sourceParameters[1], "This is the second parameter.");
		setParameterComment(sourceParameters[2], "This is the third parameter.");

		// Setup the destination parameters as desired.
		setParameterDataType(destinationParameters[0], undefined4DataType);
		setParameterDataType(destinationParameters[1], undefined4DataType);
		setParameterDataType(destinationParameters[2], undefined4DataType);
		setParameterName(destinationParameters[0], null, SourceType.DEFAULT);
		setParameterName(destinationParameters[1], "apple", SourceType.IMPORTED);
		setParameterName(destinationParameters[2], "orange", SourceType.USER_DEFINED);
		setParameterComment(destinationParameters[0], "Once upon a time...");
		setParameterComment(destinationParameters[1], null);
		setParameterComment(destinationParameters[2], null);

		// Verify the source parameters are as desired.
		checkParameterDataType(sourceParameters[0], stringPointerDataType);
		checkParameterDataType(sourceParameters[1], dWordDataType);
		checkParameterDataType(sourceParameters[2], floatDataType);
		checkParameterName(sourceParameters[0], "destination", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[1], "value", SourceType.USER_DEFINED);
		checkParameterName(sourceParameters[2], "percentage", SourceType.USER_DEFINED);
		checkParameterComment(sourceParameters[0], "This is the first parameter.");
		checkParameterComment(sourceParameters[1], "This is the second parameter.");
		checkParameterComment(sourceParameters[2], "This is the third parameter.");

		// Verify the destination parameters are as desired.
		checkParameterDataType(destinationParameters[0], undefined4DataType);
		checkParameterDataType(destinationParameters[1], undefined4DataType);
		checkParameterDataType(destinationParameters[2], undefined4DataType);
		checkParameterName(destinationParameters[0], "param_1", SourceType.DEFAULT);
		checkParameterName(destinationParameters[1], "apple", SourceType.IMPORTED);
		checkParameterName(destinationParameters[2], "orange", SourceType.USER_DEFINED);
		checkParameterComment(destinationParameters[0], "Once upon a time...");
		checkParameterComment(destinationParameters[1], null);
		checkParameterComment(destinationParameters[2], null);
	}

	private Parameter setParameterDataType(Parameter parameter, DataType dataType)
			throws InvalidInputException {

		if (parameter == null) {
			return null;
		}
		Program program = parameter.getFunction().getProgram();
		boolean commit = false;
		int transaction = program.startTransaction("Test - Set Parameter Data Type");
		try {
			parameter.setDataType(dataType, SourceType.ANALYSIS);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		return parameter;
	}

	private void checkParameterDataType(Parameter parameter, DataType expectedDataType) {
		DataType parameterDataType = parameter.getDataType();
		assertTrue("Expected " + expectedDataType + ", but was " + parameterDataType,
			expectedDataType.isEquivalent(parameterDataType));
	}

	private Parameter setParameterName(Parameter parameter, String name, SourceType sourceType)
			throws InvalidInputException, DuplicateNameException {

		if (parameter == null) {
			return null;
		}
		Program program = parameter.getFunction().getProgram();
		boolean commit = false;
		int transaction = program.startTransaction("Test - Set Parameter Name");
		try {
			parameter.setName(name, sourceType);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		return parameter;
	}

	private void checkParameterName(Parameter parameter, String expectedName,
			SourceType expectedSourceType) {
		String parameterName = parameter.getName();
		assertEquals(expectedName, parameterName);
		SourceType parameterSourceType = parameter.getSource();
		assertEquals("Expected " + expectedSourceType + ", but was " + parameterSourceType + ". ",
			expectedSourceType, parameterSourceType);
	}

	private Parameter setParameterComment(Parameter parameter, String comment) {

		if (parameter == null) {
			return null;
		}
		Program program = parameter.getFunction().getProgram();
		boolean commit = false;
		int transaction = program.startTransaction("Test - Set Parameter Comment");
		try {
			parameter.setComment(comment);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		return parameter;
	}

	private void checkParameterComment(Parameter parameter, String expectedComment) {
		String parameterComment = parameter.getComment();
		assertEquals("Expected " + expectedComment + ", but was " + parameterComment,
			expectedComment, parameterComment);
	}

	private Symbol addLabel(String name, Address address, Program program)
			throws InvalidInputException {

		SymbolTable symbolTable = program.getSymbolTable();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Add Label");
			return symbolTable.createLabel(address, name, SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private Symbol addDefaultLabel(Address address, Program program) {

		SymbolTable symbolTable = program.getSymbolTable();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Add Label");
			ReferenceManager referenceManager = program.getReferenceManager();
			referenceManager.addMemoryReference(address, address, RefType.READ,
				SourceType.USER_DEFINED, 0);
			return symbolTable.getPrimarySymbol(address);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private void setComment(Program program, Address address, int codeUnitCommentType,
			String comment) {
		Listing listing = program.getListing();

		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Add Comment: " + comment);
			listing.setComment(address, codeUnitCommentType, comment);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private VTMatch getMatch(VTMatchSet matchSet, Address sourceAddress,
			Address destinationAddress) {
		Collection<VTMatch> desiredMatches = matchSet.getMatches(sourceAddress, destinationAddress);
		assertEquals(1, desiredMatches.size());
		VTMatch matchToApply = desiredMatches.iterator().next();
		return matchToApply;
	}

	public void applyMatch(VTMatch match) {
		List<VTMatch> matches = new ArrayList<>();
		matches.add(match);
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(task);
	}

	public static VTMatchSet createMatchSetFromList(VTSessionDB db, List<AssociationPair> list)
			throws Exception {
		int testTransactionID = 0;
		try {
			testTransactionID = db.startTransaction("Test Match Set Setup");
			VTMatchSet matchSet = db.createMatchSet(
				createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));
			for (AssociationPair associationPair : list) {
				VTMatchInfo info = createRandomMatch(associationPair.getSourceAddress(),
					associationPair.getDestinationAddress(), db);
				matchSet.addMatch(info);
			}
			return matchSet;
		}
		finally {
			db.endTransaction(testTransactionID, true);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class DomainObjectListenerRecorder implements DomainObjectListener {

		List<DomainObjectChangedEvent> events = new ArrayList<>();

		@Override
		public void domainObjectChanged(DomainObjectChangedEvent ev) {
			events.add(ev);
		}
	}

	private class AssociationPair {

		private final Address sourceAddress;
		private final Address destinationAddress;

		AssociationPair(Address sourceAddress, Address destinationAddress) {
			this.sourceAddress = sourceAddress;
			this.destinationAddress = destinationAddress;
		}

		Address getSourceAddress() {
			return sourceAddress;
		}

		Address getDestinationAddress() {
			return destinationAddress;
		}
	}
}
