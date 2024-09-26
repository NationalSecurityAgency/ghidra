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
package ghidra.app.util.viewer.listingpanel;

import ghidra.app.util.SymbolPath;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.datastruct.Duo.Side;

/**
 * Class for converting a program location from one program to another
 */
public class ProgramLocationTranslator {

	private ListingAddressCorrelation correlator;

	/**
	 * Constructor given a correlator for translating addresses
	 * @param correlator converts address from one program to another
	 */
	public ProgramLocationTranslator(ListingAddressCorrelation correlator) {
		this.correlator = correlator;
	}

	/**
	 * Converts a program location from the other side to the given side.
	 * @param side the side to get a location for
	 * @param otherSideLocation the location from the other side
	 * @return a program location for the given side that matches the other given location
	 */
	public ProgramLocation getProgramLocation(Side side, ProgramLocation otherSideLocation) {
		if (correlator == null) {
			return null;
		}
		if (otherSideLocation == null) {
			return null;
		}
		if (otherSideLocation instanceof VariableLocation) {
			return getVariableLocation(side, (VariableLocation) otherSideLocation);
		}

		SaveState saveState = new SaveState();
		otherSideLocation.saveState(saveState);
		Address otherSideAddress = otherSideLocation.getAddress();

		// Try to get the indicated side's address using one of the address correlators.
		Address address = getAddress(side, otherSideAddress);
		if (address == null || address == Address.NO_ADDRESS) {
			return null; // Couldn't determine the indicated side's address.
		}

		saveState.remove("_ADDRESS");
		saveState.putString("_ADDRESS", address.toString());

		Address byteAddress = otherSideLocation.getByteAddress();
		saveState.remove("_BYTE_ADDR");
		Address desiredByteAddress = null;
		Program program = correlator.getProgram(side);
		if (byteAddress != null) {
			// Try to get the indicated side's byte address using one of the address
			// correlators or by inferring it.
			desiredByteAddress =
				inferDesiredByteAddress(otherSideAddress, address, byteAddress,
					otherSideLocation.getProgram(), program);
			if (desiredByteAddress != null) {
				saveState.putString("_BYTE_ADDR", desiredByteAddress.toString());
			}
		}

		// Adjust symbol path for labels if it is part of the location.
		adjustSymbolPath(saveState, otherSideAddress, address, byteAddress, desiredByteAddress,
			otherSideLocation.getProgram(), program);

		// ref address can't be used with indicated side so remove it.
		saveState.remove("_REF_ADDRESS");
		// Don't know how to find equivalent referenced address for the indicated side,
		// so don't put any _REF_ADDRESS back.

		return ProgramLocation.getLocation(program, saveState);

	}

	/**
	 * Gets the matching address for the given side given an address from the other side. This
	 * method first attempts to translate the address directly. If that fails, it then attempts
	 * to get an address for the start of the code unit containing the given address because the
	 * correlator may only have translations for code unit starts.
	 * 
	 * @param side the LEFT or RIGHT side to get an address for
	 * @param otherSidesAddress address the address from the other side
	 * @return the match address for the given side given an address from the other side
	 */
	private Address getAddress(Side side, Address otherSidesAddress) {
		Side otherSide = side.otherSide();
		Address address = correlator.getAddress(side, otherSidesAddress);

		if (address != null) {
			return address;
		}
		// Couldn't directly correlate the address.
		CodeUnit otherCodeUnit =
			correlator.getProgram(otherSide).getListing().getCodeUnitContaining(otherSidesAddress);
		if (otherCodeUnit == null) {
			return null; // Can't get the code unit's address.
		}
		Address otherCodeUnitAddress = otherCodeUnit.getMinAddress();
		return correlator.getAddress(side, otherCodeUnitAddress);
	}

	/**
	 * Gets an matching variable location when given a variable location from the other side.
	 * 
	 * @param side LEFT or RIGHT indicating which side's variable location is needed.
	 * @param variableLocation the variable location from the other side.
	 * @return a variable location for the desired side. Otherwise, null.
	 */
	private ProgramLocation getVariableLocation(Side side, VariableLocation variableLocation) {
		if (variableLocation == null) {
			return null;
		}
		SaveState saveState = new SaveState();
		variableLocation.saveState(saveState);
		Address address = variableLocation.getAddress();
		Address byteAddress = variableLocation.getByteAddress();
		Address functionAddress = variableLocation.getFunctionAddress();

		// Try to get the indicated side's address using one of the address correlators.
		Address desiredAddress = getAddress(side, address);
		if (desiredAddress == null || desiredAddress == Address.NO_ADDRESS) {
			return null; // Couldn't determine the indicated side's address.
		}

		// Try to use a byte address.
		Address desiredByteAddress = null;
		if (byteAddress != null) {
			desiredByteAddress = getAddress(side, byteAddress);
		}

		Address desiredFunctionAddress = null;
		if (functionAddress != null) {
			desiredFunctionAddress = getAddress(side, functionAddress);
		}
		Function function = correlator.getFunction(side);
		if ((desiredFunctionAddress == null) && (function != null)) {
			// If this is a thunk function get the thunked address.
			Function thunkedFunction = function.getThunkedFunction(true);
			if (thunkedFunction != null) {
				desiredFunctionAddress = thunkedFunction.getEntryPoint();
			}
		}

		saveState.remove("_ADDRESS");
		saveState.putString("_ADDRESS", desiredAddress.toString());

		saveState.remove("_BYTE_ADDR");
		if (desiredByteAddress != null) {
			saveState.putString("_BYTE_ADDR", desiredByteAddress.toString());
		}

		saveState.remove("_FUNC_ADDRESS");
		if (desiredFunctionAddress != null) {
			saveState.putString("_FUNC_ADDRESS", desiredFunctionAddress.toString());
		}

		// ref address can't be used with indicated side so remove it.
		saveState.remove("_REF_ADDRESS");
		// Don't know how to find equivalent referenced address for the indicated side,
		// so don't put any _REF_ADDRESS back.

		return ProgramLocation.getLocation(correlator.getProgram(side), saveState);
	}

	private void adjustSymbolPath(SaveState saveState, Address address, Address desiredAddress,
			Address byteAddress, Address desiredByteAddress, Program program,
			Program desiredProgram) {

		String[] symbolPathArray = saveState.getStrings("_SYMBOL_PATH", new String[0]);
		saveState.remove("_SYMBOL_PATH");
		if (symbolPathArray.length == 0) {
			return; // save state has no labels for program location.
		}
		Address symbolAddress = (byteAddress != null) ? byteAddress : address;
		Address desiredSymbolAddress =
			(desiredByteAddress != null) ? desiredByteAddress : desiredAddress;
		if (symbolAddress == null || desiredSymbolAddress == null) {
			return; // no address match.
		}
		Symbol[] symbols = program.getSymbolTable().getSymbols(symbolAddress);
		if (symbols.length == 0) {
			return; // no symbols in program for matching.
		}
		Symbol[] desiredSymbols = desiredProgram.getSymbolTable().getSymbols(desiredSymbolAddress);
		if (desiredSymbols.length == 0) {
			return; // no symbols in desiredProgram for matching.
		}

		int desiredRow = adjustSymbolRow(saveState, symbols, desiredSymbols);

		int desiredIndex = getDesiredSymbolIndex(desiredSymbols, desiredRow);

		// Now get the desired symbol.
		Symbol desiredSymbol = desiredSymbols[desiredIndex];
		SymbolPath symbolPath = getSymbolPath(desiredSymbol);
		// Set symbol path for desiredProgram in the save state.
		saveState.putStrings("_SYMBOL_PATH", symbolPath.asArray());
	}

	private int adjustSymbolRow(SaveState saveState, Symbol[] symbols, Symbol[] desiredSymbols) {
		// For now just try to choose the same label index if more than one.
		int row = saveState.getInt("_ROW", 0);
		int desiredRow = row;
		if (desiredRow >= desiredSymbols.length) {
			desiredRow = desiredSymbols.length - 1;
		}
		saveState.putInt("_ROW", desiredRow);
		return desiredRow;
	}

	private SymbolPath getSymbolPath(Symbol desiredSymbol) {
		String label = desiredSymbol.getName();
		Namespace namespace = desiredSymbol.getParentNamespace();
		SymbolPath symbolPath;
		if (namespace == null || namespace.isGlobal()) {
			symbolPath = new SymbolPath(label);
		}
		else {
			symbolPath = new SymbolPath(new SymbolPath(namespace.getSymbol()), label);
		}
		return symbolPath;
	}

	private int getDesiredSymbolIndex(Symbol[] desiredSymbols, int desiredRow) {

		boolean hasFunction = desiredSymbols[0].getSymbolType().equals(SymbolType.FUNCTION);

		// Get the array index of the desired symbol.
		int desiredIndex = 0; // Default to first entry in array.
		if (desiredRow >= 0 && desiredRow < desiredSymbols.length) {
			desiredIndex = desiredRow;
		}
		if (hasFunction) {
			// Last row in GUI is also first entry in array.
			if (desiredIndex == desiredSymbols.length - 1) {
				desiredIndex = 0; // Set to function element.
			}
			else {
				desiredIndex++; // Adjust for function element at start of array.
			}
		}
		return desiredIndex;
	}

	/**
	 * Infers a desired byte address based on the specified <code>byteAddress</code> as well as the
	 * <code>address</code> and <code>desiredAddress</code> that were matched.
	 * 
	 * @param address matches up with the <code>desiredAddress</code> from the other function/data.
	 * @param desiredAddress matches up with the <code>address</code> from the other function/data.
	 * @param byteAddress the byte address that is associated with <code>address</code>
	 * @param program the program for the <code>address</code> and <code>byteAddress</code>.
	 * @param desiredProgram the program for the <code>desiredAddress</code> and
	 *            <code>desiredByteAddress</code>.
	 * @return the desired byte address that matches up with the indicated <code>byteAddress</code>
	 *         or null if it can't be determined.
	 */
	private Address inferDesiredByteAddress(Address address, Address desiredAddress,
			Address byteAddress, Program program, Program desiredProgram) {

		long numBytesIntoCodeUnit = byteAddress.subtract(address);
		if (numBytesIntoCodeUnit == 0) {
			return desiredAddress;
		}
		if (numBytesIntoCodeUnit > 0) {
			CodeUnit codeUnit = program.getListing().getCodeUnitAt(address);
			CodeUnit desiredCodeUnit = desiredProgram.getListing().getCodeUnitAt(desiredAddress);
			if (codeUnit != null && desiredCodeUnit != null) {
				int desiredCodeUnitLength = desiredCodeUnit.getLength();
				if (numBytesIntoCodeUnit < desiredCodeUnitLength) {
					// Position at byte within code unit.
					return desiredAddress.add(numBytesIntoCodeUnit);
				}
				// Otherwise position at last byte of code unit.
				return desiredAddress.add(desiredCodeUnitLength - 1);
			}
		}
		return null;
	}

}
