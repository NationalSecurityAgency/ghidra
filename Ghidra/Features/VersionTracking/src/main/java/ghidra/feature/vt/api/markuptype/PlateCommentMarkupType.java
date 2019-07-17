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

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.util.*;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.CommentChoices;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.PlateFieldLocation;
import ghidra.program.util.ProgramLocation;

import java.util.List;

public class PlateCommentMarkupType extends CommentMarkupType {

//==================================================================================================
// Factory Methods
//==================================================================================================

	public static final VTMarkupType INSTANCE = new PlateCommentMarkupType();

//==================================================================================================
// End Factory Methods
//==================================================================================================

	private PlateCommentMarkupType() {
		super("Plate Comment");
	}

	@Override
	protected int getCodeUnitCommentType() {
		return CodeUnit.PLATE_COMMENT;
	}

	@Override
	protected ProgramLocation getLocation(VTAssociation association, Address address,
			boolean isSource) {
		if (address == null || address == Address.NO_ADDRESS) {
			return null;
		}

		Program program =
			isSource ? getSourceProgram(association) : getDestinationProgram(association);
		return new PlateFieldLocation(program, address, null, 0, 0, null, -1);
	}

	@Override
	public VTMatchApplyChoices.CommentChoices getCommentChoice(ToolOptions options) {
		VTMatchApplyChoices.CommentChoices commentChoice =
			options.getEnum(VTOptionDefines.PLATE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
		return commentChoice;
	}

	@Override
	public VTMarkupItemApplyActionType getApplyAction(ToolOptions options) {
		VTMatchApplyChoices.CommentChoices commentChoice =
			options.getEnum(VTOptionDefines.PLATE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
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
	public Address validateDestinationAddress(VTAssociation association, Address sourceAddress,
			Address suggestedDestinationAddress) {

		if (sourceAddress.equals(association.getSourceAddress())) {
			return association.getDestinationAddress();
		}
		return suggestedDestinationAddress;
	}

	@Override
	public Options convertOptionsToForceApplyOfMarkupItem(VTMarkupItemApplyActionType applyAction,
			ToolOptions applyOptions) {
		ToolOptions options = applyOptions.copy();
		switch (applyAction) {
			case ADD:
				options.setEnum(VTOptionDefines.PLATE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
				break;
			case ADD_AS_PRIMARY:
				throw new IllegalArgumentException(getDisplayName() +
					" markup items cannot perform an Add As Primary action.");
			case REPLACE_DEFAULT_ONLY:
				throw new IllegalArgumentException(getDisplayName() +
					" markup items cannot perform a Replace Default Only action.");
			case REPLACE:
				options.setEnum(VTOptionDefines.PLATE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
				break;
		}
		return options;
	}

	@Override
	public List<VTMarkupItem> createMarkupItems(VTAssociation association) {
		List<VTMarkupItem> markupItems = super.createMarkupItems(association);
		for (VTMarkupItem vtMarkupItem : markupItems) {
			// If we have a plate comment markup item and the source address is the 
			// source function entry point, force the destination address to be the 
			// entry point of the destination function.
			if (vtMarkupItem.getSourceAddress().equals(association.getSourceAddress())) {
				// Set Plate destination to destination function's entry point.
				vtMarkupItem.setDefaultDestinationAddress(association.getDestinationAddress(),
				VTMarkupItem.FUNCTION_ADDRESS_SOURCE);
			}
		}
		return markupItems;
	}
}
