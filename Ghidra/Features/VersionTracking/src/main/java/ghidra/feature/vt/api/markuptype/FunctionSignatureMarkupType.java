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

import java.util.*;

import ghidra.feature.vt.api.impl.MarkupItemImpl;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.stringable.FunctionSignatureStringable;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.SystemUtilities;

public class FunctionSignatureMarkupType extends FunctionEntryPointBasedAbstractMarkupType {

//==================================================================================================
// Factory Methods
//==================================================================================================

	@Override
	public List<VTMarkupItem> createMarkupItems(VTAssociation association) {

		List<VTMarkupItem> list = new ArrayList<VTMarkupItem>();

		Function sourceFunction = getSourceFunction(association);
		Function destinationFunction = getDestinationFunction(association);
		if (sourceFunction == null || destinationFunction == null) {
			return list;
		}

		Address sourceAddress = sourceFunction.getEntryPoint();

		MarkupItemImpl markupItemImpl = new MarkupItemImpl(association, this, sourceAddress);
		// Now we have a function signature markup item without a destination.
		// Force the destination address to be the entry point of the destination function.
		markupItemImpl.setDefaultDestinationAddress(association.getDestinationAddress(),
			VTMarkupItem.FUNCTION_ADDRESS_SOURCE);
		list.add(markupItemImpl);

		return list;
	}

//==================================================================================================
// End Factory Methods
//==================================================================================================

	public static final VTMarkupType INSTANCE = new FunctionSignatureMarkupType();

	private ToolOptions unapplyOptions;

	private FunctionSignatureMarkupType() {
		super("Function Signature");
	}

	@Override
	public boolean supportsApplyAction(VTMarkupItemApplyActionType applyAction) {
		return applyAction == VTMarkupItemApplyActionType.REPLACE;
	}

	@Override
	public Stringable getSourceValue(VTAssociation association, Address sourceAddress) {
		Function function = getSourceFunction(association);
		if (function == null) {
			return null;
		}
		return new FunctionSignatureStringable(function);
	}

	@Override
	public void unapplyMarkup(VTMarkupItem markupItem) throws VersionTrackingApplyException {
		if (!markupItem.canUnapply()) {
			throw new VersionTrackingApplyException(
				"Attempted to unapply a non-applied markup item");
		}

		Address destinationAddress = markupItem.getDestinationAddress();
		FunctionSignatureStringable destinationSignatureStringable =
			(FunctionSignatureStringable) markupItem.getOriginalDestinationValue();
		Program destinationProgram = getDestinationProgram(markupItem.getAssociation());
		FunctionManager functionManager = destinationProgram.getFunctionManager();
		Function destinationFunction = functionManager.getFunctionAt(destinationAddress);
		if (destinationFunction == null) {
			return;
		}

		if (destinationSignatureStringable.sameFunctionSignature(destinationFunction)) {
			return;
		}

		ToolOptions options = getUnapplyOptions();
		destinationSignatureStringable.applyFunctionSignature(destinationFunction, options, true);
	}

	private ToolOptions getUnapplyOptions() {

		if (unapplyOptions != null) {
			return unapplyOptions;
		}

		unapplyOptions = new ToolOptions(VTController.VERSION_TRACKING_OPTIONS_NAME);

		unapplyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		unapplyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.NAME_MATCH);
		unapplyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		unapplyOptions.setEnum(NO_RETURN, ReplaceChoices.REPLACE);
		unapplyOptions.setEnum(VAR_ARGS, ReplaceChoices.REPLACE);
		unapplyOptions.setEnum(CALL_FIXUP, ReplaceChoices.REPLACE);
		unapplyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		unapplyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		unapplyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		unapplyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.OVERWRITE_EXISTING);

		unapplyOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.REPLACE_ALWAYS);
		unapplyOptions.setEnum(LABELS, LabelChoices.REPLACE_ALL);

		unapplyOptions.setEnum(PLATE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		unapplyOptions.setEnum(PRE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		unapplyOptions.setEnum(END_OF_LINE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		unapplyOptions.setEnum(REPEATABLE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		unapplyOptions.setEnum(POST_COMMENT, CommentChoices.OVERWRITE_EXISTING);

		unapplyOptions.setEnum(DATA_MATCH_DATA_TYPE,
			ReplaceDataChoices.REPLACE_ALL_DATA);

		return unapplyOptions;
	}

	@Override
	public boolean applyMarkup(VTMarkupItem markupItem, ToolOptions markupOptions)
			throws VersionTrackingApplyException {

		VTMatchApplyChoices.FunctionSignatureChoices functionSignatureChoice =
			markupOptions.getEnum(VTOptionDefines.FUNCTION_SIGNATURE,
				VTOptionDefines.DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE);
		if (functionSignatureChoice == FunctionSignatureChoices.EXCLUDE) {
			throw new IllegalArgumentException("Can't apply function signature for " +
				markupItem.getMarkupType().getDisplayName() + " since it is excluded.");
		}

		Address destinationAddress = markupItem.getDestinationAddress();

		if (destinationAddress == null) {
			throw new VersionTrackingApplyException("The destination address cannot be null!");
		}

		if (destinationAddress == Address.NO_ADDRESS) {
			throw new VersionTrackingApplyException(
				"The destination address cannot be No Address!");
		}

		Program destinationProgram = getDestinationProgram(markupItem.getAssociation());

		FunctionSignatureStringable sourceStringable =
			(FunctionSignatureStringable) markupItem.getSourceValue();
		if (sourceStringable == null) {
			// someone must have deleted the function signature from the source
			throw new VersionTrackingApplyException("Cannot apply function signature" +
				".  The data from the source program no longer exists. Markup Item: " + markupItem);
		}

		FunctionManager functionManager = destinationProgram.getFunctionManager();
		Function destinationFunction = functionManager.getFunctionAt(destinationAddress);
		if (destinationFunction == null) {
			throw new VersionTrackingApplyException(
				"Couldn't find destination function to apply a name.");
		}

		if (sourceStringable.applyFunctionSignature(destinationFunction, markupOptions, false)) {
			return true;
		}
		return false;
	}

	@Override
	public ProgramLocation getDestinationLocation(VTAssociation association,
			Address destinationAddress) {
		FunctionReturnTypeFieldLocation functionReturnTypeLocation =
			getFunctionReturnTypeLocation(association, destinationAddress, false);
		if (functionReturnTypeLocation != null) {
			return functionReturnTypeLocation;
		}
		if (destinationAddress == null || destinationAddress == Address.NO_ADDRESS) {
			return null;
		}
		// Otherwise, get the address location.
		return new AddressFieldLocation(getDestinationProgram(association), destinationAddress);
	}

	@Override
	public ProgramLocation getSourceLocation(VTAssociation association, Address sourceAddress) {
		FunctionReturnTypeFieldLocation functionReturnTypeLocation =
			getFunctionReturnTypeLocation(association, sourceAddress, true);
		if (functionReturnTypeLocation != null) {
			return functionReturnTypeLocation;
		}
		// Otherwise, get the address location.
		return new AddressFieldLocation(getSourceProgram(association), sourceAddress);
	}

	private FunctionReturnTypeFieldLocation getFunctionReturnTypeLocation(
			VTAssociation association, Address address, boolean isSource) {

		if (address == null || address == Address.NO_ADDRESS) {
			return null; // Return null when there is no destination address.
		}

		Program program;
		if (isSource) {
			program = getSourceProgram(association);
		}
		else {
			program = getDestinationProgram(association);
		}

		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			return null;
		}
		Address entryAddress = function.getEntryPoint();
		Stringable value =
			isSource ? getSourceValue(association, address)
					: getCurrentDestinationValue(
						association, address);
		String displayString = (value != null) ? value.getDisplayString() : null;
		return new FunctionReturnTypeFieldLocation(program, entryAddress, displayString);
	}

	@Override
	public Stringable getCurrentDestinationValue(VTAssociation association,
			Address destinationAddress) {
		Address expectedDestinationAddress = association.getDestinationAddress();
		if (expectedDestinationAddress.equals(destinationAddress)) {
			Function function = getDestinationFunction(association);
			if (function == null) {
				return null;
			}
			return new FunctionSignatureStringable(function);
		}
		return null;
	}

	@Override
	public Stringable getOriginalDestinationValue(VTAssociation association,
			Address destinationAddress) {
		return getCurrentDestinationValue(association, destinationAddress);
	}

	@Override
	public VTMarkupItemApplyActionType getApplyAction(ToolOptions options) {

		VTMatchApplyChoices.FunctionSignatureChoices replaceDefaultChoice =
			options.getEnum(VTOptionDefines.FUNCTION_SIGNATURE,
				VTOptionDefines.DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE);
		switch (replaceDefaultChoice) {
			case REPLACE:
				return VTMarkupItemApplyActionType.REPLACE;
			case WHEN_SAME_PARAMETER_COUNT:
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
				throw new IllegalArgumentException(getDisplayName() +
					" markup items cannot perform an Add action.");
			case ADD_AS_PRIMARY:
				throw new IllegalArgumentException(getDisplayName() +
					" markup items cannot perform an Add As Primary action.");
			case REPLACE_DEFAULT_ONLY:
				throw new IllegalArgumentException(getDisplayName() +
					" markup items cannot perform a Replace Default Only action.");
			case REPLACE:
				options.setEnum(VTOptionDefines.FUNCTION_SIGNATURE,
					FunctionSignatureChoices.REPLACE);
				break;
			case REPLACE_FIRST_ONLY:
				break;
			default:
				break;
		}
		return options;
	}

	@Override
	public boolean hasSameSourceAndDestinationValues(VTMarkupItem markupItem) {

		VTAssociation association = markupItem.getAssociation();
		Function sourceFunction = getSourceFunction(association);
		Function destinationFunction = getDestinationFunction(association);
		if (sourceFunction == null || destinationFunction == null) {
			return false;
		}
		FunctionSignatureStringable sourceStringable =
			new FunctionSignatureStringable(sourceFunction);
		FunctionSignatureStringable destinationStringable =
			new FunctionSignatureStringable(destinationFunction);
		return SystemUtilities.isEqual(sourceStringable, destinationStringable);
	}

	@Override
	public boolean conflictsWithOtherMarkup(MarkupItemImpl markupItem,
			Collection<VTMarkupItem> markupItems) {
		return false;
	}
}
