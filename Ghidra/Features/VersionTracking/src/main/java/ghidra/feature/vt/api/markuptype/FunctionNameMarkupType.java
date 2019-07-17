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

import static ghidra.feature.vt.gui.util.VTOptionDefines.DEFAULT_OPTION_FOR_FUNCTION_NAME;
import static ghidra.feature.vt.gui.util.VTOptionDefines.FUNCTION_NAME;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.feature.vt.api.impl.MarkupItemImpl;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.stringable.FunctionNameStringable;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.FunctionNameChoices;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class FunctionNameMarkupType extends FunctionEntryPointBasedAbstractMarkupType {

//==================================================================================================
// Factory Methods
//==================================================================================================

	public static final VTMarkupType INSTANCE = new FunctionNameMarkupType();

//	private static final String FUNCTION_NAME = null;

	@Override
	public List<VTMarkupItem> createMarkupItems(VTAssociation association) {

		List<VTMarkupItem> list = new ArrayList<>();

		Function sourceFunction = getSourceFunction(association);
		Function destinationFunction = getDestinationFunction(association);
		if (sourceFunction == null || destinationFunction == null) {
			return list;
		}

		Address sourceAddress = sourceFunction.getEntryPoint();
		String sourceFunctionName = sourceFunction.getName();

		String defaultFunctionName = SymbolUtilities.getDefaultFunctionName(sourceAddress);
		if (sourceFunctionName.equals(defaultFunctionName)) {
			return list;
		}

		MarkupItemImpl markupItemImpl = new MarkupItemImpl(association, this, sourceAddress);
		// Now we have a function name markup item without a destination.
		// Force the destination address to be the entry point of the destination function.
		markupItemImpl.setDefaultDestinationAddress(association.getDestinationAddress(),
			VTMarkupItem.FUNCTION_ADDRESS_SOURCE);
		list.add(markupItemImpl);

		return list;
	}

//==================================================================================================
// End Factory Methods
//==================================================================================================

	private FunctionNameMarkupType() {
		super("Function Name");
	}

	@Override
	public boolean supportsApplyAction(VTMarkupItemApplyActionType applyAction) {
		return applyAction == VTMarkupItemApplyActionType.ADD ||
			applyAction == VTMarkupItemApplyActionType.ADD_AS_PRIMARY ||
			applyAction == VTMarkupItemApplyActionType.REPLACE_DEFAULT_ONLY ||
			applyAction == VTMarkupItemApplyActionType.REPLACE;
	}

	@Override
	public Stringable getSourceValue(VTAssociation association, Address sourceAddress) {
		Function function = getSourceFunction(association);
		if (function == null) {
			return null;
		}
		Symbol symbol = function.getSymbol();
		return new FunctionNameStringable(symbol);
	}

	@Override
	public void unapplyMarkup(VTMarkupItem markupItem) throws VersionTrackingApplyException {
		if (!markupItem.canUnapply()) {
			throw new VersionTrackingApplyException(
				"Attempted to unapply a non-applied markup item");
		}

		FunctionNameStringable sourceSymbolStringable =
			(FunctionNameStringable) markupItem.getSourceValue();
		Address destinationAddress = markupItem.getDestinationAddress();
		FunctionNameStringable destinationSymbolStringable =
			(FunctionNameStringable) markupItem.getOriginalDestinationValue();
		String destinationName = destinationSymbolStringable.getSymbolName();
		Program destinationProgram = getDestinationProgram(markupItem.getAssociation());
		FunctionManager functionManager = destinationProgram.getFunctionManager();
		Function destinationFunction = functionManager.getFunctionAt(destinationAddress);
		if (destinationFunction == null) {
			return;
		}
		Namespace destinationNamespace = destinationFunction.getParentNamespace();
		// If the name exists as a label then there must have been an AddAsPrimary.
		SymbolTable symbolTable = destinationProgram.getSymbolTable();
		Symbol desiredSymbol =
			symbolTable.getSymbol(destinationName, destinationAddress, destinationNamespace);
		if (desiredSymbol != null && desiredSymbol.getSymbolType() == SymbolType.LABEL) {
			SetLabelPrimaryCmd setLabelPrimaryCmd =
				new SetLabelPrimaryCmd(desiredSymbol.getAddress(), desiredSymbol.getName(),
					desiredSymbol.getParentNamespace());
			setLabelPrimaryCmd.applyTo(destinationProgram);
		}

		String currentName = destinationFunction.getName();
		if (currentName.equals(destinationName)) {
			// Don't need to change the function name, but may need to remove the source name as a label.
			String sourceName = sourceSymbolStringable.getSymbolName();
			Symbol sourceAsLabel =
				symbolTable.getSymbol(sourceName, destinationAddress, destinationNamespace);
			if (sourceAsLabel != null) {
				sourceAsLabel.delete();
			}
			return;
		}
		try {
			destinationSymbolStringable.applyFunctionName(destinationProgram, destinationFunction);
		}
		catch (DuplicateNameException e) {
			throw new VersionTrackingApplyException(
				"Unable to restore function name: " + destinationName, e);
		}
		catch (InvalidInputException e) {
			throw new VersionTrackingApplyException(
				"Unable to restore function name: " + destinationName, e);
		}
		catch (CircularDependencyException e) {
			throw new VersionTrackingApplyException("Unable to restore function name: " +
				destinationName + " due to circular dependancy on namespaces", e);
		}
	}

	@Override
	public boolean applyMarkup(VTMarkupItem markupItem, ToolOptions markupOptions)
			throws VersionTrackingApplyException {

		VTMatchApplyChoices.FunctionNameChoices functionNameChoice =
			markupOptions.getEnum(FUNCTION_NAME, DEFAULT_OPTION_FOR_FUNCTION_NAME);
		if (functionNameChoice == FunctionNameChoices.EXCLUDE) {
			throw new IllegalArgumentException("Can't apply " +
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
		FunctionManager functionManager = destinationProgram.getFunctionManager();
		Function destinationFunction = functionManager.getFunctionAt(destinationAddress);
		if (destinationFunction == null) {
			throw new VersionTrackingApplyException(
				"Couldn't find destination function to apply a name.");
		}
		Symbol destinationSymbol = destinationFunction.getSymbol();

		if (functionNameChoice == FunctionNameChoices.REPLACE_DEFAULT_ONLY &&
			destinationSymbol.getSource() != SourceType.DEFAULT) {
			return false; // can't do it because we should only replace default names
		}

		FunctionNameStringable symbolStringable =
			(FunctionNameStringable) markupItem.getSourceValue();
		if (symbolStringable == null) {
			// someone must have deleted the variable from the source
			throw new VersionTrackingApplyException("Cannot apply function name" +
				".  The function from the source program no longer exists. Markup Item: " +
				markupItem);
		}

		if (symbolStringable.getSymbolSourceType() == SourceType.DEFAULT) {
			return false; // Can't set a default source name on the destination.
		}

		String name = symbolStringable.getSymbolName();

		try {
			boolean isPrimary = (functionNameChoice == FunctionNameChoices.ADD_AS_PRIMARY);
			if (functionNameChoice == FunctionNameChoices.ADD || isPrimary) {
				if (destinationFunction.isExternal()) {
					throw new VersionTrackingApplyException("Can't add the function name \"" +
						name + "\" to the external function \"" + destinationFunction.getName() +
						"\". External function names can only be replaced.");
				}
				// Now check to see which should be primary.
				symbolStringable.addFunctionName(destinationProgram, destinationFunction,
					isPrimary);
			}
			else {
				symbolStringable.applyFunctionName(destinationProgram, destinationFunction);
			}
		}
		catch (DuplicateNameException e) {
			throw new VersionTrackingApplyException(
				"Unable to apply function name: " + name + " due to a duplicate name", e);
		}
		catch (InvalidInputException e) {
			throw new VersionTrackingApplyException(
				"Unable to apply function name: " + name + " due to invalid input", e);
		}
		catch (CircularDependencyException e) {
			throw new VersionTrackingApplyException("Unable to apply function name: " + name +
				" due to circular dependancy on namespaces", e);
		}
		return true;
	}

	@Override
	public ProgramLocation getDestinationLocation(VTAssociation association,
			Address destinationAddress) {
		Address defaultDestinationAddress = association.getDestinationAddress();

		// Ignore the destinationAddress that is handed in and instead use the association
		// destination address that should be the destination function's entry point.
		FunctionNameFieldLocation functionNameLocation =
			getFunctionNameLocation(association, defaultDestinationAddress, false);
		if (functionNameLocation != null) {
			return functionNameLocation;
		}

		// Otherwise, get the primary symbol location.
		LabelFieldLocation labelLocation =
			getPrimaryLabelLocation(association, defaultDestinationAddress, false);
		if (labelLocation != null) {
			return labelLocation;
		}

		// Otherwise, get the address location.
		Program program = getDestinationProgram(association);
		return new AddressFieldLocation(program, defaultDestinationAddress);
	}

	@Override
	public ProgramLocation getSourceLocation(VTAssociation association, Address sourceAddress) {
		Address defaultSourceAddress = association.getSourceAddress();
		// Ignore the sourceAddress that is handed in and instead use the association
		// source address that should be the source function's entry point.
		FunctionNameFieldLocation functionNameLocation =
			getFunctionNameLocation(association, defaultSourceAddress, true);
		if (functionNameLocation != null) {
			return functionNameLocation;
		}

		// Otherwise, get the primary symbol location.
		LabelFieldLocation labelLocation =
			getPrimaryLabelLocation(association, defaultSourceAddress, true);
		if (labelLocation != null) {
			return labelLocation;
		}

		// Otherwise, get the address location.
		Program program = getSourceProgram(association);
		return new AddressFieldLocation(program, defaultSourceAddress);
	}

	private FunctionNameFieldLocation getFunctionNameLocation(VTAssociation association,
			Address address, boolean isSource) {
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
		FunctionNameStringable value =
			(FunctionNameStringable) (isSource ? getSourceValue(association, address)
					: getCurrentDestinationValue(association, address));
		String name = (value != null) ? value.getSymbolName() : "";
		return new FunctionNameFieldLocation(program, entryAddress, name);
	}

	private LabelFieldLocation getPrimaryLabelLocation(VTAssociation association, Address address,
			boolean isSource) {
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

		Symbol primarySymbol = program.getSymbolTable().getPrimarySymbol(address);
		if (primarySymbol == null) {
			return null;
		}
		return new LabelFieldLocation(primarySymbol);
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
			String functionName = function.getName();
			Namespace namespace = function.getParentNamespace();
			Program program = getDestinationProgram(association);
			Address address = association.getDestinationAddress();
			SymbolTable symbolTable = program.getSymbolTable();
			Symbol symbol = symbolTable.getSymbol(functionName, address, namespace);
			return new FunctionNameStringable(symbol);
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
		VTMatchApplyChoices.FunctionNameChoices functionNameChoice =
			options.getEnum(FUNCTION_NAME, DEFAULT_OPTION_FOR_FUNCTION_NAME);
		switch (functionNameChoice) {
			case ADD:
			case ADD_AS_PRIMARY:
				return VTMarkupItemApplyActionType.ADD;
			case REPLACE_DEFAULT_ONLY:
			case REPLACE_ALWAYS:
				return VTMarkupItemApplyActionType.REPLACE;
			case EXCLUDE:
			default:
				return null;
		}
	}

	@Override
	public Options convertOptionsToForceApplyOfMarkupItem(VTMarkupItemApplyActionType applyAction,
			ToolOptions applyOptions) {
		Options options = applyOptions.copy();
		switch (applyAction) {
			case ADD:
				applyOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.ADD);
				break;
			case ADD_AS_PRIMARY:
				applyOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.ADD_AS_PRIMARY);
				break;
			case REPLACE_DEFAULT_ONLY:
				applyOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.REPLACE_DEFAULT_ONLY);
				break;
			case REPLACE:
				applyOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.REPLACE_ALWAYS);
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
		String sourceName = sourceFunction.getName();
		String destinationName = destinationFunction.getName();
		return sourceName.equals(destinationName);
	}
}
