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
import ghidra.feature.vt.api.stringable.MultipleSymbolStringable;
import ghidra.feature.vt.api.util.*;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.LabelChoices;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.LabelFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitorAdapter;

public class LabelMarkupType extends VTMarkupType {

//==================================================================================================
// Factory Methods
//==================================================================================================

	public static final VTMarkupType INSTANCE = new LabelMarkupType();

	@Override
	public List<VTMarkupItem> createMarkupItems(VTAssociation association) {

		List<VTMarkupItem> list = new ArrayList<>();

		addLabelMarkup(list, association);

		return list;
	}

	private void addLabelMarkup(List<VTMarkupItem> list, VTAssociation association) {
		VTSession session = association.getSession();
		Program sourceProgram = session.getSourceProgram();
		Listing sourceListing = sourceProgram.getListing();
		SymbolTable sourceSymbolTable = sourceProgram.getSymbolTable();
		Address sourceAddress = association.getSourceAddress();
		FunctionManager functionManager = sourceProgram.getFunctionManager();
		Function sourceFunction = functionManager.getFunctionAt(sourceAddress);
		AddressSetView addressSet;
		if (sourceFunction == null) {
			CodeUnit codeUnit = sourceListing.getCodeUnitAt(sourceAddress);
			Address minAddress = codeUnit == null ? sourceAddress : codeUnit.getMinAddress();
			Address maxAddress = codeUnit == null ? sourceAddress : codeUnit.getMaxAddress();
			addressSet = new AddressSet(minAddress, maxAddress);
		}
		else {
			addressSet = sourceFunction.getBody();
		}
		SymbolIterator primarySymbolIterator =
			sourceSymbolTable.getPrimarySymbolIterator(addressSet, true);
		while (primarySymbolIterator.hasNext()) {
			Symbol symbol = primarySymbolIterator.next();
			addLabelMarkup(list, association, sourceProgram, symbol.getAddress());
		}
	}

	private Symbol[] getLabelMarkupSymbols(Program sourceProgram, Address sourceAddress) {
		SymbolTable sourceSymbolTable = sourceProgram.getSymbolTable();
		Symbol[] sourceSymbols = sourceSymbolTable.getSymbols(sourceAddress);
		sourceSymbols = removeFunctionSymbol(sourceSymbols, sourceProgram.getFunctionManager());
		return sourceSymbols;
	}

	private Symbol[] getNonDefaultLabelMarkupSymbols(Program sourceProgram, Address sourceAddress) {
		SymbolTable sourceSymbolTable = sourceProgram.getSymbolTable();
		Symbol sourceSymbol = sourceSymbolTable.getPrimarySymbol(sourceAddress);
		if ((sourceSymbol == null) || (sourceSymbol.isDynamic())) {
			return new Symbol[0];
		}

		Symbol[] sourceSymbols = sourceSymbolTable.getSymbols(sourceAddress);
		sourceSymbols = removeFunctionSymbol(sourceSymbols, sourceProgram.getFunctionManager());

		return sourceSymbols;
	}

	private void addLabelMarkup(List<VTMarkupItem> list, VTAssociation association,
			Program sourceProgram, Address sourceAddress) {

		Symbol[] sourceSymbols = getNonDefaultLabelMarkupSymbols(sourceProgram, sourceAddress);
		if (sourceSymbols.length == 0) {
			return; // Don't add label markup if no symbols.
		}

		final MarkupItemImpl markupItemImpl = new MarkupItemImpl(association, this, sourceAddress);
		list.add(markupItemImpl);
	}

	private Symbol[] removeFunctionSymbol(Symbol[] symbols, FunctionManager functionManager) {
		ArrayList<Symbol> list = new ArrayList<>();
		for (Symbol symbol : symbols) {
			if (symbol.isPrimary() &&
				(functionManager.getFunctionAt(symbol.getAddress()) != null)) {
				continue; // Ignore the function symbol.
			}
			list.add(symbol);
		}
		return list.toArray(new Symbol[list.size()]);
	}

//==================================================================================================
// End Factory Methods
//==================================================================================================

	private LabelMarkupType() {
		super("Label");
	}

	@Override
	public boolean supportsApplyAction(VTMarkupItemApplyActionType applyAction) {
		return applyAction == VTMarkupItemApplyActionType.ADD ||
			applyAction == VTMarkupItemApplyActionType.ADD_AS_PRIMARY ||
			applyAction == VTMarkupItemApplyActionType.REPLACE_DEFAULT_ONLY ||
			applyAction == VTMarkupItemApplyActionType.REPLACE;
	}

	@Override
	public boolean supportsAssociationType(VTAssociationType matchType) {
		return true;
	}

	@Override
	public VTMarkupItemApplyActionType getApplyAction(ToolOptions options) {
		VTMatchApplyChoices.LabelChoices labelChoice =
			options.getEnum(VTOptionDefines.LABELS, LabelChoices.ADD);
		switch (labelChoice) {
			case ADD:
				return VTMarkupItemApplyActionType.ADD;
			case ADD_AS_PRIMARY:
				return VTMarkupItemApplyActionType.ADD;
			case REPLACE_DEFAULT_ONLY:
				return VTMarkupItemApplyActionType.REPLACE;
			case REPLACE_ALL:
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
				applyOptions.setEnum(VTOptionDefines.LABELS, LabelChoices.ADD);
			case ADD_AS_PRIMARY:
				applyOptions.setEnum(VTOptionDefines.LABELS, LabelChoices.ADD_AS_PRIMARY);
			case REPLACE_DEFAULT_ONLY:
				applyOptions.setEnum(VTOptionDefines.LABELS, LabelChoices.REPLACE_DEFAULT_ONLY);
				break;
			case REPLACE:
				applyOptions.setEnum(VTOptionDefines.LABELS, LabelChoices.REPLACE_ALL);
				break;
		}
		return options;
	}

	private Symbol[] getSourceSymbols(VTAssociation association, Address sourceAddress) {
		Program program = getSourceProgram(association);
		return getNonDefaultLabelMarkupSymbols(program, sourceAddress);
	}

	@Override
	public Stringable getSourceValue(VTAssociation association, Address sourceAddress) {
		return new MultipleSymbolStringable(getSourceSymbols(association, sourceAddress));
	}

	@Override
	public boolean applyMarkup(VTMarkupItem markupItem, ToolOptions markupOptions)
			throws VersionTrackingApplyException {

		VTMatchApplyChoices.LabelChoices labelChoice =
			markupOptions.getEnum(LABELS, DEFAULT_OPTION_FOR_LABELS);
		if (labelChoice == LabelChoices.EXCLUDE) {
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

		VTAssociation association = markupItem.getAssociation();
		MultipleSymbolStringable sourceStringable =
			(MultipleSymbolStringable) getSourceValue(association, markupItem.getSourceAddress());
		MultipleSymbolStringable destinationStringable =
			(MultipleSymbolStringable) getCurrentDestinationValue(markupItem.getAssociation(),
				destinationAddress);
		boolean replaceAll = labelChoice == LabelChoices.REPLACE_ALL;
		boolean replaceDefault =
			(labelChoice == LabelChoices.REPLACE_DEFAULT_ONLY) && (destinationStringable == null ||
				destinationStringable.isEmpty() || destinationStringable.containsDynamic());

		if (replaceAll) {
			LabelMarkupUtils.removeAllLabels(getDestinationProgram(association),
				destinationAddress);
		}

		Program destinationProgram = getDestinationProgram(association);
		try {
			boolean setAsPrimary = (labelChoice == LabelChoices.ADD_AS_PRIMARY);
			sourceStringable.setSymbols(destinationProgram, destinationAddress, setAsPrimary);
		}
		catch (DuplicateNameException e) {
			throw new VersionTrackingApplyException(
				"Unable to apply symbol(s) at address " + destinationAddress +
					" due to a duplicate name: " + sourceStringable.getDisplayString(),
				e);
		}
		catch (InvalidInputException e) {
			throw new VersionTrackingApplyException("Unable to apply symbol(s) at address " +
				destinationAddress + " due to invalid input", e);
		}
		return true;
	}

	@Override
	public void unapplyMarkup(VTMarkupItem markupItem) throws VersionTrackingApplyException {
		VTMarkupItemStatus status = markupItem.getStatus();
		if (status == VTMarkupItemStatus.DONT_CARE) {
			return; // nothing to do, as we did not change our state in the first place
		}

		Program destinationProgram = getDestinationProgram(markupItem.getAssociation());
		Address appliedAddress = markupItem.getDestinationAddress();
		LabelMarkupUtils.removeAllLabels(destinationProgram, appliedAddress);

		MultipleSymbolStringable destinationStringable =
			(MultipleSymbolStringable) markupItem.getOriginalDestinationValue();
		if (destinationStringable == null) {
			return;
		}

		try {
			destinationStringable.setSymbols(destinationProgram, appliedAddress, true);
		}
		catch (DuplicateNameException e) {
			throw new VersionTrackingApplyException("Unable to restore symbols at address: " +
				appliedAddress + " due to a duplicate name", e);
		}
		catch (InvalidInputException e) {
			throw new VersionTrackingApplyException(
				"Unable to restore symbols at address: " + appliedAddress + " due to invalid input",
				e);
		}

		// If the function name is in the source list but not the destination list then delete it.
		FunctionManager functionManager = destinationProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(appliedAddress);
		if (function != null) {
			MultipleSymbolStringable sourceStringable =
				(MultipleSymbolStringable) markupItem.getSourceValue();
			Symbol symbol = function.getSymbol();
			if (sourceStringable != null && sourceStringable.contains(symbol) &&
				!destinationStringable.contains(symbol)) {
				destinationProgram.getSymbolTable().removeSymbolSpecial(symbol);
			}
		}
	}

	@Override
	public ProgramLocation getDestinationLocation(VTAssociation association,
			Address destinationAddress) {
		if (destinationAddress == null || destinationAddress == Address.NO_ADDRESS) {
			return null;
		}
		Program destinationProgram = getDestinationProgram(association);

		Symbol primarySymbol =
			destinationProgram.getSymbolTable().getPrimarySymbol(destinationAddress);
		if (primarySymbol == null) {
			return new ProgramLocation(destinationProgram, destinationAddress);
		}
		return new LabelFieldLocation(primarySymbol);
	}

	@Override
	public ProgramLocation getSourceLocation(VTAssociation association, Address sourceAddress) {
		if (sourceAddress == null) {
			return null;
		}
		Program sourceProgram = getSourceProgram(association);

		Symbol primarySymbol = sourceProgram.getSymbolTable().getPrimarySymbol(sourceAddress);
		if (primarySymbol == null) {
			return new ProgramLocation(sourceProgram, sourceAddress);
		}
		return new LabelFieldLocation(primarySymbol);

	}

	private Symbol[] getDestinationSymbols(VTAssociation association, Address destinationAddress) {
		Symbol[] symbols = new Symbol[0];
		if (destinationAddress != null && destinationAddress != Address.NO_ADDRESS) {
			Program program = getDestinationProgram(association);
			symbols = getLabelMarkupSymbols(program, destinationAddress);
		}
		return symbols;
	}

	@Override
	public Stringable getCurrentDestinationValue(VTAssociation association,
			Address destinationAddress) {
		return new MultipleSymbolStringable(getDestinationSymbols(association, destinationAddress));
	}

	@Override
	public Stringable getOriginalDestinationValue(VTAssociation association,
			Address destinationAddress) {
		Stringable appliedMarkupOriginalValue = null;
		try {
			appliedMarkupOriginalValue = getOriginalDestinationValueForAppliedMarkupOfThisType(
				association, destinationAddress, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
			// For now this shouldn't get a cancel.
			// If it does then this falls through to the getDestinationValue() call.
		}
		if (appliedMarkupOriginalValue != null) {
			return appliedMarkupOriginalValue;
		}
		return getCurrentDestinationValue(association, destinationAddress);
	}

	@Override
	public boolean hasSameSourceAndDestinationValues(VTMarkupItem markupItem) {
		VTAssociation association = markupItem.getAssociation();
		Address sourceAddress = markupItem.getSourceAddress();
		Address destinationAddress = markupItem.getDestinationAddress();
		// Show labels that don't yet have a destination.
		if (destinationAddress == null || destinationAddress == Address.NO_ADDRESS) {
			return false;
		}
		Symbol[] sourceSymbols = getSourceSymbols(association, sourceAddress);
		Symbol[] destinationSymbols = getDestinationSymbols(association, destinationAddress);
		String[] sourceNames = getSymbolNames(sourceSymbols);
		String[] destinationNames = getSymbolNames(destinationSymbols);
		Arrays.sort(sourceNames);
		Arrays.sort(destinationNames);

		return SystemUtilities.isArrayEqual(sourceNames, destinationNames);
	}

	private String[] getSymbolNames(Symbol[] symbols) {
		int length = symbols.length;
		String[] names = new String[length];
		for (int index = 0; index < length; index++) {
			names[index] = symbols[index].getName();
		}
		return names;
	}
}
