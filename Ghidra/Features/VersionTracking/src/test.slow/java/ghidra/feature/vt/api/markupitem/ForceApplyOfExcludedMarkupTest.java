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

import static ghidra.feature.vt.gui.util.VTOptionDefines.*;
import static org.junit.Assert.*;

import java.util.Collection;
import java.util.List;

import org.junit.Test;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.*;
import ghidra.feature.vt.gui.task.ForceApplyMarkupItemTask;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitorAdapter;

public class ForceApplyOfExcludedMarkupTest extends AbstractFunctionSignatureMarkupTest {

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

	//  addPerson 004011a0   FUN... 00411830    2 params
	//  call_Strncpy 0x00411ab0   FUN... 0x00411a90    3 params w/ matching types

	public ForceApplyOfExcludedMarkupTest() {
		super();
	}

	@Test
	public void testForceApplyForExcludedFunctionName() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		// Check initial values
		checkFunctionNames("Call_strncpy_s", "FUN_00411a90");
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		// Set the function name options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.EXCLUDE);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);
		checkFunctionNameStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		// Test Apply of Function Name Markup
		List<VTMarkupItem> functionNameMarkupItems =
			getSpecificTypeOfMarkup(FunctionNameMarkupType.class, testMatch, true);
		assertEquals(1, functionNameMarkupItems.size());
		forceMarkup(functionNameMarkupItems);

		// Verify the markup was applied.
		checkFunctionNames("Call_strncpy_s", "Call_strncpy_s");
		checkMatchStatus(VTAssociationStatus.ACCEPTED);
		checkFunctionNameStatus(testMatch, VTMarkupItemStatus.ADDED);
	}

	@Test
	public void testForceApplyForExcludedFunctionName2() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");
		setFunctionName(destinationFunction, "MyCallStrncpy", SourceType.USER_DEFINED);

		// Check initial values
		checkFunctionNames("Call_strncpy_s", "MyCallStrncpy");
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void MyCallStrncpy(char * param_1, char * param_2, rsize_t param_3)");

		// Set the function name options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.EXCLUDE);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);
		checkFunctionNameStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		// Test Apply of Function Name Markup
		List<VTMarkupItem> functionNameMarkupItems =
			getSpecificTypeOfMarkup(FunctionNameMarkupType.class, testMatch, true);
		assertEquals(1, functionNameMarkupItems.size());
		forceMarkup(functionNameMarkupItems);

		// Verify the markup was applied.
		checkFunctionNames("Call_strncpy_s", "Call_strncpy_s");
		checkMatchStatus(VTAssociationStatus.ACCEPTED);
		checkFunctionNameStatus(testMatch, VTMarkupItemStatus.ADDED);
	}

	@Test
	public void testForceApplyForExcludedFunctionSignature() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");
		SourceType[] originalSourceTypes = getParameterSourceTypes(sourceFunction);

		// Check initial values
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.EXCLUDE);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		// Test Apply of Signature Markup
		List<VTMarkupItem> signatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, signatureMarkupItems.size());
		forceFunctionSignatureMarkup(signatureMarkupItems);

		// Verify the markup was applied.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		checkMatchStatus(VTAssociationStatus.ACCEPTED);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkDestinationParameterNameSourceTypes(originalSourceTypes);
	}

	@Test
	public void testForceApplyForExcludedPlateComment() throws Exception {
		genericTestForceApplyForExcludedComment(PlateCommentMarkupType.class,
			CodeUnit.PLATE_COMMENT, PLATE_COMMENT);
	}

	@Test
	public void testForceApplyForExcludedPreComment() throws Exception {
		genericTestForceApplyForExcludedComment(PreCommentMarkupType.class, CodeUnit.PRE_COMMENT,
			PRE_COMMENT);
	}

	@Test
	public void testForceApplyForExcludedEOLComment() throws Exception {
		genericTestForceApplyForExcludedComment(EolCommentMarkupType.class, CodeUnit.EOL_COMMENT,
			END_OF_LINE_COMMENT);
	}

	@Test
	public void testForceApplyForExcludeRepeatableComment() throws Exception {
		genericTestForceApplyForExcludedComment(RepeatableCommentMarkupType.class,
			CodeUnit.REPEATABLE_COMMENT, REPEATABLE_COMMENT);
	}

	@Test
	public void testForceApplyForExcludedPostComment() throws Exception {
		genericTestForceApplyForExcludedComment(PostCommentMarkupType.class, CodeUnit.POST_COMMENT,
			POST_COMMENT);
	}

	private void genericTestForceApplyForExcludedComment(
			Class<? extends CommentMarkupType> commentMarkupClass, int commentType,
			String vtOptionName) throws Exception {

		useMatch("0x00411ab0", "0x00411a90");
		sourceAddress = sourceFunction.getEntryPoint();
		destinationAddress = destinationFunction.getEntryPoint();
		setComment(sourceProgram, sourceAddress, commentType, "Source comment.");
		setComment(destinationProgram, destinationAddress, commentType, "Destination comment.");

		// Check initial values
		checkComments(commentType, sourceAddress, "Source comment.", destinationAddress,
			"Destination comment.");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(vtOptionName, CommentChoices.EXCLUDE);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);
		checkCommentStatus(testMatch, commentType, VTMarkupItemStatus.UNAPPLIED);

		// Test Apply of Comment Markup
		List<VTMarkupItem> commentMarkupItems =
			getSpecificTypeOfMarkup(commentMarkupClass, testMatch, true);
		assertTrue(commentMarkupItems.size() > 0);
		forceMarkup(commentMarkupItems);

		// Verify the markup was applied.
		checkComments(commentType, sourceAddress, "Source comment.", destinationAddress,
			"Destination comment.\nSource comment.");
		checkMatchStatus(VTAssociationStatus.ACCEPTED);
		checkCommentStatus(testMatch, commentType, VTMarkupItemStatus.ADDED);
	}

	//----------------------------

	protected void checkComments(final int commentType, final Address sourceAddr,
			final String expectedSourceComment, final Address destinationAddr,
			final String expectedDestinationComment) {

		final String[] sourceStringBox = new String[1];
		final String[] destinationStringBox = new String[1];

		runSwing(() -> {
			Listing sourceListing = sourceProgram.getListing();
			Listing destinationListing = destinationProgram.getListing();
			sourceStringBox[0] = sourceListing.getComment(commentType, sourceAddr);
			destinationStringBox[0] = destinationListing.getComment(commentType, destinationAddr);
		});

		assertEquals(expectedSourceComment, sourceStringBox[0]);
		assertEquals(expectedDestinationComment, destinationStringBox[0]);
	}

	protected void checkFunctionNames(String expectedSourceName, String expectedDestinationName) {

		final String[] sourceStringBox = new String[1];
		final String[] destinationStringBox = new String[1];

		runSwing(() -> {
			sourceStringBox[0] = sourceFunction.getName();
			destinationStringBox[0] = destinationFunction.getName();
		});

		assertEquals(expectedSourceName, sourceStringBox[0]);
		assertEquals(expectedDestinationName, destinationStringBox[0]);
	}

	protected void checkFunctionNameStatus(VTMatch match, VTMarkupItemStatus expectedStatus) {
		VTMarkupItem markupItem = getFunctionNameMarkup(match);
		if (expectedStatus == null && markupItem == null) {
			return;
		}
		assertNotNull(markupItem);
		checkMarkupStatus(markupItem, expectedStatus);
	}

	protected VTMarkupItem getFunctionNameMarkup(VTMatch match) {
		MatchInfo matchInfo = controller.getMatchInfo(match);
		Collection<VTMarkupItem> appliableMarkupItems =
			matchInfo.getAppliableMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR);
		for (VTMarkupItem vtMarkupItem : appliableMarkupItems) {
			if (vtMarkupItem.getMarkupType() instanceof FunctionNameMarkupType) {
				return vtMarkupItem;
			}
		}
		return null;
	}

	protected void checkCommentStatus(VTMatch match, int commentType,
			VTMarkupItemStatus expectedStatus) {
		VTMarkupItem markupItem = getCommentMarkup(match, commentType);
		if (expectedStatus == null && markupItem == null) {
			return;
		}
		assertNotNull(markupItem);
		checkMarkupStatus(markupItem, expectedStatus);
	}

	protected VTMarkupItem getCommentMarkup(VTMatch match, int commentType) {
		MatchInfo matchInfo = controller.getMatchInfo(match);
		Collection<VTMarkupItem> appliableMarkupItems =
			matchInfo.getAppliableMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR);
		for (VTMarkupItem vtMarkupItem : appliableMarkupItems) {
			switch (commentType) {
				case CodeUnit.PLATE_COMMENT:
					if (vtMarkupItem.getMarkupType() instanceof PlateCommentMarkupType) {
						return vtMarkupItem;
					}
					continue;
				case CodeUnit.PRE_COMMENT:
					if (vtMarkupItem.getMarkupType() instanceof PreCommentMarkupType) {
						return vtMarkupItem;
					}
					continue;
				case CodeUnit.EOL_COMMENT:
					if (vtMarkupItem.getMarkupType() instanceof EolCommentMarkupType) {
						return vtMarkupItem;
					}
					continue;
				case CodeUnit.REPEATABLE_COMMENT:
					if (vtMarkupItem.getMarkupType() instanceof RepeatableCommentMarkupType) {
						return vtMarkupItem;
					}
					continue;
				case CodeUnit.POST_COMMENT:
					if (vtMarkupItem.getMarkupType() instanceof PostCommentMarkupType) {
						return vtMarkupItem;
					}
					continue;
			}
		}
		return null;
	}

	protected void forceMarkup(List<VTMarkupItem> markupItems) {
		ForceApplyMarkupItemTask task =
			new ForceApplyMarkupItemTask(session, markupItems, controller.getOptions());
		runTask(task);
		waitOnPossibleBackgroundProcessing();
	}

	protected void setComment(Program program, Address address, int commentType, String comment) {
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Set Comment: " + address.toString(true));
			Listing listing = program.getListing();
			listing.setComment(address, commentType, comment);
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
}
