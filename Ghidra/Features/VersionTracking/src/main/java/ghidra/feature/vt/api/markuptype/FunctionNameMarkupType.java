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

import static ghidra.feature.vt.gui.util.VTMatchApplyChoices.FunctionNameChoices.*;
import static ghidra.feature.vt.gui.util.VTOptionDefines.*;

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
import ghidra.program.model.address.GlobalNamespace;
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

	@Override
	public List<VTMarkupItem> createMarkupItems(VTAssociation association) {

		List<VTMarkupItem> list = new ArrayList<>();

		Function srcFunction = getSourceFunction(association);
		Function destinationFunction = getDestinationFunction(association);
		if (srcFunction == null || destinationFunction == null) {
			return list;
		}

		Address srcAddress = srcFunction.getEntryPoint();
		String srcFunctionName = srcFunction.getName();

		String defaultFunctionName = SymbolUtilities.getDefaultFunctionName(srcAddress);
		if (srcFunctionName.equals(defaultFunctionName)) {
			Namespace namespace = srcFunction.getParentNamespace();
			if (namespace instanceof GlobalNamespace) {
				// default function name in the default namespace--nothing to be applied
				return list;
			}
		}

		// Now we have a function name markup item without a destination.
		// Force the destination address to be the entry point of the destination function.
		MarkupItemImpl markupItemImpl = new MarkupItemImpl(association, this, srcAddress);
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

		FunctionNameStringable srcStringable = (FunctionNameStringable) markupItem.getSourceValue();
		Address destAddress = markupItem.getDestinationAddress();
		FunctionNameStringable destStringable =
			(FunctionNameStringable) markupItem.getOriginalDestinationValue();
		Program destProgram = getDestinationProgram(markupItem.getAssociation());
		FunctionManager fm = destProgram.getFunctionManager();
		Function destFunction = fm.getFunctionAt(destAddress);
		if (destFunction == null) {
			return;
		}

		// If a symbol with the original name exist as a label, then there must have been an 
		// AddAsPrimary operation that made the source symbol primary, replacing the original 
		// destination symbol as primary.
		restorePrimarySymbol(destAddress, destStringable, destProgram);

		unapplyFunctionName(srcStringable, destAddress, destStringable, destFunction);
	}

	private void restorePrimarySymbol(Address destAddress, FunctionNameStringable destStringable,
			Program destProgram) {

		SymbolTable symbolTable = destProgram.getSymbolTable();
		String originalSymbolName = destStringable.getSymbolName();
		String destinationNamespace = destStringable.getSymbolNamespace();
		Symbol originalSymbol =
			getSymbol(symbolTable, originalSymbolName, destAddress, destinationNamespace);
		if (originalSymbol == null) {
			return; // deleted by the user
		}

		if (originalSymbol.getSymbolType() != SymbolType.LABEL) {
			return;
		}

		if (originalSymbol.isPrimary()) {
			return; // nothing to do
		}

		Address address = originalSymbol.getAddress();
		String name = originalSymbol.getName();
		Namespace ns = originalSymbol.getParentNamespace();
		SetLabelPrimaryCmd setLabelPrimaryCmd = new SetLabelPrimaryCmd(address, name, ns);
		setLabelPrimaryCmd.applyTo(destProgram);
	}

	private Symbol getSymbol(SymbolTable symbolTable, String name, Address address,
			String namespacePath) {

		String expectedNamespacePath = namespacePath;
		if (expectedNamespacePath == null) {
			expectedNamespacePath = "Global";
		}
		Symbol[] symbols = symbolTable.getSymbols(address);
		for (Symbol s : symbols) {
			String symbolName = s.getName();
			if (!symbolName.equals(name)) {
				continue;
			}

			Namespace namespace = s.getParentNamespace();
			String symbolNamespacePath = namespace.getName(true);
			if (symbolNamespacePath.equals(expectedNamespacePath)) {
				return s;
			}
		}
		return null;
	}

	private void unapplyFunctionName(FunctionNameStringable sourceStringable, Address destAddress,
			FunctionNameStringable destStringable, Function destFunction)
			throws VersionTrackingApplyException {

		String originalFunctionName = destStringable.getSymbolName(true);
		String currentFunctionName = destFunction.getName(true);
		if (currentFunctionName.equals(originalFunctionName)) {

			// The full function name and namespace are unchanged.  Assume only a label was added.
			Namespace destNamespace = destFunction.getParentNamespace();
			Program destProgram = destFunction.getProgram();
			SymbolTable symbolTable = destProgram.getSymbolTable();
			String srcName = sourceStringable.getSymbolName();
			Symbol srcAsLabel = symbolTable.getSymbol(srcName, destAddress, destNamespace);
			if (srcAsLabel != null) {
				srcAsLabel.delete();
				return;
			}

			// try the label with the source namespace
			String srcNsString = sourceStringable.getSymbolNamespace();
			srcAsLabel = getSymbol(symbolTable, srcName, destAddress, srcNsString);
			if (srcAsLabel != null) {
				srcAsLabel.delete();
				return;
			}

			// try the label in the global namespace
			srcAsLabel = getSymbol(symbolTable, srcName, destAddress, null);
			if (srcAsLabel != null) {
				srcAsLabel.delete();
			}
			return;
		}

		try {
			destStringable.unapplyFunctionNameAndNamespace(destFunction);
		}
		catch (DuplicateNameException e) {
			throw new VersionTrackingApplyException(
				"Unable to restore function name: " + originalFunctionName, e);
		}
		catch (InvalidInputException e) {
			throw new VersionTrackingApplyException(
				"Unable to restore function name: " + originalFunctionName, e);
		}
		catch (CircularDependencyException e) {
			throw new VersionTrackingApplyException("Unable to restore function name: " +
				originalFunctionName + " due to circular dependancy on namespaces", e);
		}
	}

	@Override
	public boolean applyMarkup(VTMarkupItem markupItem, ToolOptions markupOptions)
			throws VersionTrackingApplyException {

		VTMatchApplyChoices.FunctionNameChoices nameChoice =
			markupOptions.getEnum(FUNCTION_NAME, DEFAULT_OPTION_FOR_FUNCTION_NAME);
		if (nameChoice == EXCLUDE) {
			throw new IllegalArgumentException("Can't apply " +
				markupItem.getMarkupType().getDisplayName() + " since it is excluded.");
		}

		Address destAddress = markupItem.getDestinationAddress();
		if (destAddress == null) {
			throw new VersionTrackingApplyException("The destination address cannot be null!");
		}

		if (destAddress == Address.NO_ADDRESS) {
			throw new VersionTrackingApplyException(
				"The destination address cannot be No Address!");
		}

		Program destProgram = getDestinationProgram(markupItem.getAssociation());
		FunctionManager fm = destProgram.getFunctionManager();
		Function destFunction = fm.getFunctionAt(destAddress);
		if (destFunction == null) {
			throw new VersionTrackingApplyException(
				"Couldn't find destination function to apply a name.");
		}

		Symbol destSymbol = destFunction.getSymbol();
		SourceType destSource = destSymbol.getSource();
		if (nameChoice == REPLACE_DEFAULT_ONLY && destSource != SourceType.DEFAULT) {
			return false; // can't do it because we should only replace default names
		}

		FunctionNameStringable srcStringable =
			(FunctionNameStringable) markupItem.getSourceValue();
		if (srcStringable == null) {
			// someone must have deleted the variable from the source
			throw new VersionTrackingApplyException("Cannot apply function name" +
				".  The function from the source program no longer exists. Markup Item: " +
				markupItem);
		}

		Function srcFunction = getSourceFunction(markupItem.getAssociation());
		boolean replaceNamespace = markupOptions.getBoolean(USE_NAMESPACE_FUNCTIONS,
			DEFAULT_OPTION_FOR_NAMESPACE_FUNCTIONS);
		if (!hasAnythingToApply(srcStringable, srcFunction, replaceNamespace)) {
			return false;
		}

		if (cannotAddDefaultSymbol(nameChoice, srcStringable)) {
			return false;
		}

		applyFunctionName(nameChoice, srcFunction, destFunction, srcStringable, replaceNamespace);
		return true;
	}

	private boolean cannotAddDefaultSymbol(FunctionNameChoices nameChoice,
			FunctionNameStringable sourceStringable) {

		if (nameChoice == ADD || nameChoice == ADD_AS_PRIMARY) {
			SourceType srcSourceType = sourceStringable.getSymbolSourceType();
			if (srcSourceType == SourceType.DEFAULT) {
				return true; // cannot add a default symbol 
			}
		}

		return false;
	}

	private boolean hasAnythingToApply(FunctionNameStringable srcStringable, Function srcFunction,
			boolean replaceNamespace) {

		if (srcStringable.getSymbolSourceType() != SourceType.DEFAULT) {
			return true; // non-default name to apply
		}

		Namespace srcNamespace = srcFunction.getParentNamespace();
		if (srcNamespace instanceof GlobalNamespace) {
			// default name and default namespace--nothing to apply
			return false;
		}

		// Default name; non-default namespace.  We can apply the namespace if the option is on
		return replaceNamespace;

	}

	private void applyFunctionName(FunctionNameChoices nameChoice, Function srcFunction,
			Function destFunction, FunctionNameStringable srcStringable, boolean replaceNamespace)
			throws VersionTrackingApplyException {

		String name = srcStringable.getSymbolName();
		try {
			doApplyFunctionName(nameChoice, srcFunction, destFunction, srcStringable,
				replaceNamespace);
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
	}

	private void doApplyFunctionName(FunctionNameChoices nameChoice, Function srcFunction,
			Function destFunction, FunctionNameStringable srcStringable, boolean replaceNamespace)
			throws VersionTrackingApplyException, DuplicateNameException, InvalidInputException,
			CircularDependencyException {

		if (nameChoice == REPLACE_ALWAYS || nameChoice == REPLACE_DEFAULT_ONLY) {
			if (replaceNamespace) {
				srcStringable.applyFunctionNameAndNamespace(destFunction);
			}
			else {
				srcStringable.applyFunctionName(destFunction);
			}
			return;
		}

		// An ADD or ADD_AS_PRIMARY
		if (destFunction.isExternal()) {
			String srcName = srcStringable.getSymbolName();
			String destName = destFunction.getName();
			String msg = "Can't add function name '%s' to external function '%s'. " +
				"External function names can only be replaced.";
			String formatted = msg.formatted(srcName, destName);
			throw new VersionTrackingApplyException(formatted);
		}

		boolean isPrimary = (nameChoice == ADD_AS_PRIMARY);
		if (replaceNamespace) {
			srcStringable.addFunctionNameAndNamespace(srcFunction, destFunction, isPrimary);
		}
		else {
			srcStringable.addFunctionName(destFunction, isPrimary);
		}
	}

	@Override
	public ProgramLocation getDestinationLocation(VTAssociation association, Address destAddress) {

		Address defaultDestAddress = association.getDestinationAddress();

		// Ignore the destinationAddress that is handed in and instead use the association
		// destination address that should be the destination function's entry point.
		FunctionNameFieldLocation functionNameLocation =
			getFunctionNameLocation(association, defaultDestAddress, false);
		if (functionNameLocation != null) {
			return functionNameLocation;
		}

		// Otherwise, get the primary symbol location.
		LabelFieldLocation labelLocation =
			getPrimaryLabelLocation(association, defaultDestAddress, false);
		if (labelLocation != null) {
			return labelLocation;
		}

		// Otherwise, get the address location.
		Program program = getDestinationProgram(association);
		return new AddressFieldLocation(program, defaultDestAddress);
	}

	@Override
	public ProgramLocation getSourceLocation(VTAssociation association, Address sourceAddress) {

		// Ignore the sourceAddress that is handed in and instead use the association
		// source address that should be the source function's entry point.
		Address defaultSourceAddress = association.getSourceAddress();
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
	public Stringable getCurrentDestinationValue(VTAssociation association, Address destAddress) {

		Address expectedDestAddress = association.getDestinationAddress();
		if (!expectedDestAddress.equals(destAddress)) {
			return null;
		}

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
				applyOptions.setEnum(FUNCTION_NAME, ADD);
				break;
			case ADD_AS_PRIMARY:
				applyOptions.setEnum(FUNCTION_NAME, ADD_AS_PRIMARY);
				break;
			case REPLACE_DEFAULT_ONLY:
				applyOptions.setEnum(FUNCTION_NAME, REPLACE_DEFAULT_ONLY);
				break;
			case REPLACE:
				applyOptions.setEnum(FUNCTION_NAME, REPLACE_ALWAYS);
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
		String sourceName = sourceFunction.getName(true);
		String destinationName = destinationFunction.getName(true);
		return sourceName.equals(destinationName);
	}
}
