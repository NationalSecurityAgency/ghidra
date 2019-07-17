/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.feature.vt.api.impl.MarkupItemImpl;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.stringable.FunctionSignatureStringable;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.feature.vt.gui.util.*;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.FunctionSignatureChoices;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.SystemUtilities;

import java.util.*;

public class FunctionSignatureMarkupType extends FunctionEntryPointBasedAbstractMarkupType {

//==================================================================================================
// Factory Methods
//==================================================================================================

	public static final VTMarkupType INSTANCE = new FunctionSignatureMarkupType();

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

		destinationSignatureStringable.applyFunctionSignature(destinationFunction,
			VT_UNAPPLY_MARKUP_OPTIONS, true);
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

		ToolOptions adjustedOptions = markupOptions.copy();
//		switch (functionSignatureChoice) {
//			case REPLACE:
//				adjustedOptions.putEnum(VTOptionDefines.FUNCTION_SIGNATURE,
//					FunctionSignatureChoices.REPLACE);
//				break;
//			case WHEN_SAME_PARAMETER_COUNT:
//				adjustedOptions.putEnum(VTOptionDefines.FUNCTION_SIGNATURE,
//					FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
//				break;
//			case WHEN_TAKING_SIGNATURE:
//				// Don't apply the names. The function signature will do it if needed.
//				return false;
//			default:
//				throw new IllegalArgumentException("Unsupported apply action: " + applyAction);
//
//		}

		Address destinationAddress = markupItem.getDestinationAddress();

		if (destinationAddress == null) {
			throw new VersionTrackingApplyException("The destination address cannot be null!");
		}

		if (destinationAddress == Address.NO_ADDRESS) {
			throw new VersionTrackingApplyException("The destination address cannot be No Address!");
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
		if (sourceStringable.applyFunctionSignature(destinationFunction, adjustedOptions, false)) {
//			// If the function signature was applied, apply the names if necessary.
//			applyParameterNamesIfNeeded(markupItem, adjustedOptions);
//			// If the function signature was applied, apply the no return flag if necessary.
//			applyNoReturnIfNeeded(markupItem, adjustedOptions);
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
			isSource ? getSourceValue(association, address) : getCurrentDestinationValue(
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
