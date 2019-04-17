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

import static ghidra.feature.vt.api.main.VTMarkupItemApplyActionType.ADD;
import static ghidra.feature.vt.api.main.VTMarkupItemApplyActionType.REPLACE;
import static ghidra.feature.vt.db.VTTestUtils.addr;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.feature.vt.api.db.VTAssociationDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.*;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.CommentChoices;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class CommentMarkupItemTest extends AbstractVTMarkupItemTest {

	public CommentMarkupItemTest() {
		super();
	}

@Test
    public void testFindAndApplyMarkupItem_Merge_WithNonNullDestinationValue() throws Exception {
		String sourceComment = "Hi mom merge";
		String destinationComment = "Hi dad merge";
		String appliedComment = destinationComment + '\n' + sourceComment;

		String commentAddressString = "0x01002d06";
		Address commentAddress = addr(commentAddressString, destinationProgram);
		setComment(sourceProgram, sourceComment, commentAddress);
		setComment(destinationProgram, destinationComment, commentAddress);

		CommentValidator validator =
			new CommentValidator("0x01002cf5", "0x01002cf5", commentAddress, sourceComment,
				destinationComment, appliedComment, CodeUnit.EOL_COMMENT,
				CommentChoices.APPEND_TO_EXISTING);
		doTestFindAndApplyMarkupItem(validator);
	}

@Test
    public void testFindAndApplyMarkupItem_Merge_WithNullDestinationValue() throws Exception {
		String sourceComment = "Hi mom merge";
		String destinationComment = null;
		String appliedComment = sourceComment;

		String commentAddressString = "0x01002d06";
		Address commentAddress = addr(commentAddressString, destinationProgram);
		setComment(sourceProgram, sourceComment, commentAddress);
		setComment(destinationProgram, destinationComment, commentAddress);

		CommentValidator validator =
			new CommentValidator("0x01002cf5", "0x01002cf5", commentAddress, sourceComment,
				destinationComment, appliedComment, CodeUnit.EOL_COMMENT,
				CommentChoices.APPEND_TO_EXISTING);
		doTestFindAndApplyMarkupItem(validator);
	}

@Test
    public void testFindAndApplyMarkupItem_Replace_WithNonNullDestinationValue() throws Exception {
		String sourceComment = "Hi mom merge";
		String destinationComment = "Hi dad merge";
		String appliedComment = sourceComment;

		String commentAddressString = "0x01002d06";
		Address commentAddress = addr(commentAddressString, destinationProgram);
		setComment(sourceProgram, sourceComment, commentAddress);
		setComment(destinationProgram, destinationComment, commentAddress);

		CommentValidator validator =
			new CommentValidator("0x01002cf5", "0x01002cf5", commentAddress, sourceComment,
				destinationComment, appliedComment, CodeUnit.EOL_COMMENT,
				CommentChoices.OVERWRITE_EXISTING);
		doTestFindAndApplyMarkupItem(validator);
	}

@Test
    public void testFindAndApplyMarkupItem_Replace_WithNullDestinationValue() throws Exception {
		String sourceComment = "Hi mom merge";
		String destinationComment = null;
		String appliedComment = sourceComment;

		String commentAddressString = "0x01002d06";
		Address commentAddress = addr(commentAddressString, destinationProgram);
		setComment(sourceProgram, sourceComment, commentAddress);
		setComment(destinationProgram, destinationComment, commentAddress);

		CommentValidator validator =
			new CommentValidator("0x01002cf5", "0x01002cf5", commentAddress, sourceComment,
				destinationComment, appliedComment, CodeUnit.EOL_COMMENT,
				CommentChoices.OVERWRITE_EXISTING);
		doTestFindAndApplyMarkupItem(validator);
	}

@Test
    public void testFindAndApplyMarkupItem_IgnoreAction() throws Exception {
		String sourceComment = "Hi mom merge";
		String destinationComment = null;
		String appliedComment = destinationComment; // the comment is not applied

		String commentAddressString = "0x01002d06";
		Address commentAddress = addr(commentAddressString, destinationProgram);
		setComment(sourceProgram, sourceComment, commentAddress);
		setComment(destinationProgram, destinationComment, commentAddress);

		CommentValidator validator =
			new CommentValidator("0x01002cf5", "0x01002cf5", commentAddress, sourceComment,
				destinationComment, appliedComment, CodeUnit.EOL_COMMENT, CommentChoices.EXCLUDE);
		doTestFindAndApplyMarkupItem(validator);
	}

//==================================================================================================
// Private Methods
//==================================================================================================    

	private void setComment(Program program, String comment, Address address) {
		Listing listing = program.getListing();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Add Comment: " + comment);
			listing.setComment(address, CodeUnit.EOL_COMMENT, comment);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class CommentValidator extends TestDataProviderAndValidator {

		protected Address sourceFunctionAddress;
		protected Address destinationFunctionAddress;
		private final Address commentAddress;
		private final String sourceComment;
		private final String destinationComment;
		private final String appliedComment;
		private final int commentType;
		private CommentChoices commentChoice;

		CommentValidator(String sourceFunctionAddress, String destinationFunctionAddress,
				Address commentAddress, String sourceComment, String destinationComment,
				String appliedComment, int commentType, CommentChoices commentChoice) {
			this.commentChoice = commentChoice;
			this.sourceFunctionAddress = addr(sourceFunctionAddress, sourceProgram);
			this.destinationFunctionAddress = addr(destinationFunctionAddress, destinationProgram);
			this.commentAddress = commentAddress;
			this.sourceComment = sourceComment;
			this.destinationComment = destinationComment;
			this.appliedComment = appliedComment;
			this.commentType = commentType;
		}

		@Override
		protected Address getDestinationApplyAddress() {
			return commentAddress;
		}

		@Override
		protected VTMarkupItemApplyActionType getApplyAction() {
			if (commentChoice == CommentChoices.EXCLUDE) {
				return null;
			}
			if (commentChoice == CommentChoices.APPEND_TO_EXISTING) {
				return ADD;
			}
			return REPLACE;
		}

		@Override
		protected Address getDestinationMatchAddress() {
			return destinationFunctionAddress;
		}

		@Override
		protected Address getSourceMatchAddress() {
			return sourceFunctionAddress;
		}

		@Override
		protected VTMarkupItem searchForMarkupItem(VTMatch match) throws Exception {
			List<VTMarkupItem> items =
				createCommentMarkupItems((VTAssociationDB) match.getAssociation());
			assertTrue("Did not find any comment markup items", (items.size() >= 1));
			return items.get(0);
		}

		private List<VTMarkupItem> createCommentMarkupItems(VTAssociationDB association) {

			List<VTMarkupItem> list = new ArrayList<VTMarkupItem>();
			list.addAll(EolCommentMarkupType.INSTANCE.createMarkupItems(association));
			list.addAll(PlateCommentMarkupType.INSTANCE.createMarkupItems(association));
			list.addAll(PostCommentMarkupType.INSTANCE.createMarkupItems(association));
			list.addAll(PreCommentMarkupType.INSTANCE.createMarkupItems(association));
			list.addAll(RepeatableCommentMarkupType.INSTANCE.createMarkupItems(association));
			return list;
		}

		@Override
		protected void assertApplied() {
			Listing listing = destinationProgram.getListing();
			String comment = listing.getComment(commentType, commentAddress);
			assertEquals("Comment was not applied for " + commentChoice.name(), appliedComment,
				comment);
		}

		@Override
		protected void assertUnapplied() {
			Listing listing = destinationProgram.getListing();
			String comment = listing.getComment(commentType, commentAddress);
			assertEquals("Comment was not applied for " + commentChoice.name(), destinationComment,
				comment);
		}

		@Override
		protected ToolOptions getOptions() {
			ToolOptions options = super.getOptions().copy();
			options.setEnum(getOptionName(), commentChoice);
			return options;
		}

		private String getOptionName() {
			switch (commentType) {
				case CodeUnit.EOL_COMMENT:
					return VTOptionDefines.END_OF_LINE_COMMENT;
				case CodeUnit.PLATE_COMMENT:
					return VTOptionDefines.PLATE_COMMENT;
				case CodeUnit.POST_COMMENT:
					return VTOptionDefines.POST_COMMENT;
				case CodeUnit.PRE_COMMENT:
					return VTOptionDefines.PRE_COMMENT;
				case CodeUnit.REPEATABLE_COMMENT:
					return VTOptionDefines.REPEATABLE_COMMENT;
				default:
					return null;
			}
		}
	}

}
