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

import static ghidra.feature.vt.gui.util.VTOptionDefines.*;

import java.util.Collection;
import java.util.List;

import ghidra.feature.vt.api.impl.MarkupItemImpl;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class VTMarkupType {

	static final ToolOptions VT_UNAPPLY_MARKUP_OPTIONS =
		new ToolOptions(VTController.VERSION_TRACKING_OPTIONS_NAME);
	static {
		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(CALLING_CONVENTION, CallingConventionChoices.NAME_MATCH);
		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(INLINE, ReplaceChoices.REPLACE);
		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(NO_RETURN, ReplaceChoices.REPLACE);
		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(VAR_ARGS, ReplaceChoices.REPLACE);
		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(CALL_FIXUP, ReplaceChoices.REPLACE);
		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(PARAMETER_COMMENTS, CommentChoices.OVERWRITE_EXISTING);

		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(FUNCTION_NAME, FunctionNameChoices.REPLACE_ALWAYS);
		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(LABELS, LabelChoices.REPLACE_ALL);

		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(PLATE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(PRE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(END_OF_LINE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(REPEATABLE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(POST_COMMENT, CommentChoices.OVERWRITE_EXISTING);

		VT_UNAPPLY_MARKUP_OPTIONS.setEnum(DATA_MATCH_DATA_TYPE,
			ReplaceDataChoices.REPLACE_ALL_DATA);
	}

	private final String name;

	public VTMarkupType(String name) {
		this.name = name;
	}

	public String getDisplayName() {
		return name;
	}

	public abstract boolean supportsAssociationType(VTAssociationType matchType);

	public abstract List<VTMarkupItem> createMarkupItems(VTAssociation associationDB);

	public abstract boolean applyMarkup(VTMarkupItem markupItem, ToolOptions markupOptions)
			throws VersionTrackingApplyException;

	public abstract void unapplyMarkup(VTMarkupItem markupItem)
			throws VersionTrackingApplyException;

	public abstract VTMarkupItemApplyActionType getApplyAction(ToolOptions options);

	public abstract boolean supportsApplyAction(VTMarkupItemApplyActionType applyAction);

	public Address validateDestinationAddress(VTAssociation association, Address sourceAddress,
			Address suggestedDestinationAddress) {
		// normal markup migrators accept any address given
		return suggestedDestinationAddress;

	}

	public abstract ProgramLocation getSourceLocation(VTAssociation association,
			Address sourceAddress);

	public abstract Stringable getSourceValue(VTAssociation association, Address source);

	public abstract ProgramLocation getDestinationLocation(VTAssociation association,
			Address destinationAddress);

	public abstract Stringable getCurrentDestinationValue(VTAssociation association,
			Address destinationAddress);

	public abstract Stringable getOriginalDestinationValue(VTAssociation association,
			Address destinationAddress);

	protected Stringable getOriginalDestinationValueForAppliedMarkupOfThisType(
			VTAssociation association, Address destinationAddress, TaskMonitor monitor)
			throws CancelledException {

		if ((destinationAddress == null) || destinationAddress == Address.NO_ADDRESS) {
			return null;
		}

		Collection<VTMarkupItem> markupItems = association.getMarkupItems(monitor);
		for (VTMarkupItem markupItem : markupItems) {
			if ((markupItem.getMarkupType() == this) && markupItem.canUnapply()) {
				Address itemDestination = markupItem.getDestinationAddress();
				if (destinationAddress.equals(itemDestination)) {
					// Return the original destination value for the first applied 
					// markup item we find of this type at this address.
					return markupItem.getOriginalDestinationValue();
				}
			}
		}

		return null;
	}

	/**
	 * Returns true if both the source and destination have the same value such that there is
	 * nothing to apply.
	 * @param markupItem the markup item to check for having the save source and desination values.
	 * @return true if both the source and destination have the same value such that there is
	 * nothing to apply.
	 */
	public abstract boolean hasSameSourceAndDestinationValues(VTMarkupItem markupItem);

//==================================================================================================
// Program Object Convenience Methods
//==================================================================================================    

	public Program getDestinationProgram(VTAssociation association) {
		VTSession session = association.getSession();
		return session.getDestinationProgram();
	}

	public Program getSourceProgram(VTAssociation association) {
		VTSession session = association.getSession();
		return session.getSourceProgram();
	}

	public Listing getDestinationListing(VTAssociation association) {
		Program program = getDestinationProgram(association);
		return program.getListing();
	}

	public Listing getSourceListing(VTAssociation association) {
		Program program = getSourceProgram(association);
		return program.getListing();
	}

	public Function getSourceFunction(VTAssociation association) {
		VTSession session = association.getSession();
		Program program = session.getSourceProgram();
		Address sourceAddress = association.getSourceAddress();
		FunctionManager functionManager = program.getFunctionManager();
		return functionManager.getFunctionAt(sourceAddress);
	}

	public Function getDestinationFunction(VTAssociation association) {
		VTSession session = association.getSession();
		Program program = session.getDestinationProgram();
		Address destinationAddress = association.getDestinationAddress();
		FunctionManager functionManager = program.getFunctionManager();
		return functionManager.getFunctionAt(destinationAddress);
	}

	/**
	 * Get the address for the specified program location that is appropriate for this markup
	 * type to use as a source or destination address.
	 * @param loc the program location.
	 * @param program the program the location is associated with. This must be provided
	 * here as a parameter since the location usually doesn't contain the program and
	 * some markup types will need it to obtain an address.
	 * @return the appropriate address for this markup type (or null if there is no appropriate type.)
	 */
	public Address getAddress(ProgramLocation loc, Program program) {
		return loc.getAddress();
	}

	/**
	 * Determines whether applying a markup item of this type conflicts with any other markup
	 * items that are already applied.
	 * @param markupItem the markup item for this markup type.
	 * @param markupItems the markup items to check to see if any conflict with this markup type.
	 * @return true if another markup items conflicts with the one of this markup type.
	 */
	public boolean conflictsWithOtherMarkup(MarkupItemImpl markupItem,
			Collection<VTMarkupItem> markupItems) {
		return false;
	}

	/**
	 * Creates a new options object from the options that are passed to this method. The options 
	 * will be modified so that the specified apply action will occur for this markup type if
	 * it is a valid action for this markup.
	 * @param applyAction the desired apply action (ADD, ADD_AS_PRIMARY, REPLACE_DEFAULT_ONLY, 
	 * and REPLACE) for the markup type.
	 * @param applyOptions the original options settings that are to be modified.
	 * @return a new Options object that has been changed to result in the action for this markup type.
	 */
	public abstract Options convertOptionsToForceApplyOfMarkupItem(
			VTMarkupItemApplyActionType applyAction, ToolOptions applyOptions);
}
