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
package ghidra.feature.vt.api.markuptype;

import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTMarkupItemApplyActionType;
import ghidra.feature.vt.gui.util.*;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.CommentChoices;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.PostCommentFieldLocation;
import ghidra.program.util.ProgramLocation;

public class PostCommentMarkupType extends CommentMarkupType {

//==================================================================================================
// Factory Methods
//==================================================================================================

	public static final VTMarkupType INSTANCE = new PostCommentMarkupType();

//==================================================================================================
// End Factory Methods
//==================================================================================================

	private PostCommentMarkupType() {
		super("Post Comment");
	}

	@Override
	protected int getCodeUnitCommentType() {
		return CodeUnit.POST_COMMENT;
	}

	@Override
	protected ProgramLocation getLocation(VTAssociation association, Address address,
			boolean isSource) {
		if (address == null || address == Address.NO_ADDRESS) {
			return null;
		}

		Program program =
			isSource ? getSourceProgram(association) : getDestinationProgram(association);
		return new PostCommentFieldLocation(program, address, null, null, 0, 0);
	}

	@Override
	public VTMatchApplyChoices.CommentChoices getCommentChoice(ToolOptions options) {
		VTMatchApplyChoices.CommentChoices commentChoice =
			options.getEnum(VTOptionDefines.POST_COMMENT, CommentChoices.APPEND_TO_EXISTING);
		return commentChoice;
	}

	@Override
	public VTMarkupItemApplyActionType getApplyAction(ToolOptions options) {
		VTMatchApplyChoices.CommentChoices commentChoice =
			options.getEnum(VTOptionDefines.POST_COMMENT, CommentChoices.APPEND_TO_EXISTING);
		switch (commentChoice) {
			case APPEND_TO_EXISTING:
				return VTMarkupItemApplyActionType.ADD;
			case OVERWRITE_EXISTING:
				return VTMarkupItemApplyActionType.REPLACE;
			case EXCLUDE:
			default:
				return null;
		}
	}

	@Override
	public Options convertOptionsToForceApplyOfMarkupItem(VTMarkupItemApplyActionType applyAction,
			ToolOptions applyOptions) {
		ToolOptions options = applyOptions.copy();
		switch (applyAction) {
			case ADD:
				options.setEnum(VTOptionDefines.POST_COMMENT, CommentChoices.APPEND_TO_EXISTING);
				break;
			case ADD_AS_PRIMARY:
				throw new IllegalArgumentException(getDisplayName() +
					" markup items cannot perform an Add As Primary action.");
			case REPLACE_DEFAULT_ONLY:
				throw new IllegalArgumentException(getDisplayName() +
					" markup items cannot perform a Replace Default Only action.");
			case REPLACE:
				options.setEnum(VTOptionDefines.POST_COMMENT, CommentChoices.OVERWRITE_EXISTING);
				break;
		}
		return options;
	}
}
