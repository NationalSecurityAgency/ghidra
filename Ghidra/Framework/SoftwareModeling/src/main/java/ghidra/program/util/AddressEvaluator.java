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
package ghidra.program.util;

import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.util.List;

import generic.expressions.*;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

/**
 * Class for evaluating expressions as an Address. See 
 * {@link ExpressionOperator} for the full list of supported operators. All values are interpreted
 * as longs or symbols that resolve to an address.
 * <P>
 * ExpressionEvaluators can operate in either decimal or hex mode. If in hex mode, all numbers are
 * assumed to be hexadecimal values. In decimal mode, numbers are assumed to be decimal values, but
 * hexadecimal values can still be specified by prefixing them with "0x".
 * <P>
 * There are also two convenience static methods that can be called to evaluate address expressions.
 * These methods will either return an Address as the result or null if there was an error
 * evaluating the expression. To get error messages related to parsing the expression, instantiate 
 * an AddressEvaluator and call {@link #parseAsAddress(String)} which will throw a 
 * {@link ExpressionException} when the expression can't be evaluated.
 */
public class AddressEvaluator extends ExpressionEvaluator {

	private Reference<Program> programReference;
	private AddressFactory addressFactory;
	private AddressSpace preferredSpace;

	/**
	 * Gets a valid address for the specified program as indicated by the input expression. 
	 * @param p the program to use for determining the address.
	 * @param inputExpression string representation of the address desired.
	 * @return the address. Otherwise, return null if the string fails to evaluate
	 * to a unique legitimate address.
	 */
	public static Address evaluate(Program p, String inputExpression) {
		return evaluate(p, null, inputExpression);
	}

	/**
	 * Gets a valid address for the specified program as indicated by the input expression.
	 * @param p the program to use for determining the address.
	 * @param baseAddr the base address to use for relative addressing.
	 * @param inputExpression string representation of the address desired.
	 * @return the address. Otherwise, return null if the string fails to evaluate
	 * to a unique legitimate address.
	 */
	public static Address evaluate(Program p, Address baseAddr, String inputExpression) {
		AddressEvaluator evaluator = new AddressEvaluator(p, true);
		try {
			return evaluator.parseAsRelativeAddress(inputExpression, baseAddr);
		}
		catch (ExpressionException e) {
			return null;
		}
	}

	/**
	 * Constructs an AddressEvalutor for the given program and in the specified hex/decimal mode.
	 * @param program the program to use to evaluate expressions into valid addresses.
	 * @param assumeHex if true, all numeric values are assumed to be hexadecimal numbers.
	 */
	public AddressEvaluator(Program program, boolean assumeHex) {
		this(program, null, assumeHex);
	}

	/**
	 * Constructs an AdddressEvaluator without a full program. This version will not be able to
	 * evaluate symbol or memory block names. This is mostly for backwards compatibility.
	 * @param factory the address factory for creating addresses
	 * @param assumeHex if true, all numeric values are assumed to be hexadecimal numbers.
	 */
	public AddressEvaluator(AddressFactory factory, boolean assumeHex) {
		this(factory, null, assumeHex);
	}

	/**
	 * Constructs an AddressEvalutor for the given program and in the specified hex/decimal mode.
	 * @param program the program to use to evaluate expressions into valid addresses.
	 * @param defaultSpace The address space to use when converting long values into addresses. If
	 * this value is null, then the default address space will be used.
	 * @param assumeHex if true, all numeric values are assumed to be hexadecimal numbers.
	 */
	public AddressEvaluator(Program program, AddressSpace defaultSpace, boolean assumeHex) {
		this(program.getAddressFactory(), defaultSpace, assumeHex);
		this.programReference = new WeakReference<>(program);
	}

	private AddressEvaluator(AddressFactory factory, AddressSpace defaultSpace, boolean assumeHex) {
		super(assumeHex);
		this.addressFactory = factory;
		this.preferredSpace = defaultSpace;
	}

	/**
	 * Evaluates the given input expression as an address.
	 * @param input the expression to evaluate
	 * @return the Address the expression evaluates to
	 * @throws ExpressionException if the input expression can't be evaluated to a valid, unique
	 * address.
	 */
	public Address parseAsAddress(String input) throws ExpressionException {
		return this.parseAsRelativeAddress(input, null);
	}

	/**
	 * Evaluates the given input expression as a relative offset that will be added to the given
	 * base address.
	 * @param input the expression to evaluate as an offset
	 * @param baseAddress the base address the evaluted expression will be added to to get the 
	 * resulting address.
	 * @return the Address after the evaluated offset is added to the given base address.
	 * @throws ExpressionException if the input expression can't be evaluated to a valid, unique
	 * address.
	 */
	public Address parseAsRelativeAddress(String input, Address baseAddress)
			throws ExpressionException {
		ExpressionValue expressionValue = baseAddress == null ? parse(input)
				: parse(input, new AddressExpressionValue(baseAddress));

		if (expressionValue instanceof AddressExpressionValue addressValue) {
			return validateAddressSpace(addressValue.getAddress());
		}
		if (expressionValue instanceof LongExpressionValue longValue) {
			long offset = longValue.getLongValue();
			AddressSpace space = getAddressSpace();
			try {
				return space.getAddressInThisSpaceOnly(offset);
			}
			catch (AddressOutOfBoundsException e) {
				throw new ExpressionException(e.getMessage());
			}
		}
		throw new ExpressionException("Expression did not evalute to a long! Got a " +
			expressionValue.getClass() + " instead.");

	}

	/**
	 * Returns the {@link AddressFactory} being used by this address evaluator
	 * @return the {@link AddressFactory} being used by this address evaluator
	 */
	public AddressFactory getAddressFactory() {
		return addressFactory;
	}

	/**
	 * Sets the {@link AddressSpace} to be used to convert long values into addresses. 
	 * @param space the address space to convert long values into addresses
	 */
	public void setPreferredAddressSpace(AddressSpace space) {
		this.preferredSpace = space;
	}

	// checks if the given address's address space is compatible with the preferred address space
	private Address validateAddressSpace(Address address) throws ExpressionException {
		if (preferredSpace == null) {
			return address;
		}
		AddressSpace space = address.getAddressSpace();
		if (space.equals(preferredSpace)) {
			return address;
		}
		if (isOverlayRelated(space, preferredSpace)) {
			return preferredSpace.getAddress(address.getOffset());
		}
		throw new ExpressionException("Selected address space is not compatible with expression!");
	}

	private boolean isOverlayRelated(AddressSpace space1, AddressSpace space2) {
		AddressSpace base1 = getBaseSpace(space1);
		AddressSpace base2 = getBaseSpace(space2);
		return base1.equals(base2);
	}

	private AddressSpace getBaseSpace(AddressSpace space) {
		if (space instanceof OverlayAddressSpace overlaySpace) {
			return overlaySpace.getOverlayedSpace();
		}
		return space;
	}

	private AddressSpace getAddressSpace() {
		if (preferredSpace != null) {
			return preferredSpace;
		}
		return addressFactory.getDefaultAddressSpace();
	}

	@Override
	protected ExpressionValue evaluateSymbol(String input) {
		Address address = addressFactory.getAddress(input);
		if (address != null) {
			return new AddressExpressionValue(address);
		}

		Program program = getProgram();
		if (program != null) {
			return getAddressForProgram(program, input);
		}

		return null;
	}

	private ExpressionValue getAddressForProgram(Program program, String input) {
		Address address = getAddressForSymbol(program, input);
		if (address == null) {
			address = getAddressFromMemoryMap(program, input);
		}

		return address == null ? null : new AddressExpressionValue(address);
	}

	private Address getAddressFromMemoryMap(Program program, String input) {
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(input);
		if (block != null) {
			return block.getStart();
		}
		return null;
	}

	private Address getAddressForSymbol(Program program, String input) {
		SymbolPath symbolPath = new SymbolPath(input);
		String symbolName = symbolPath.getName();
		SymbolPath parent = symbolPath.getParent();

		Namespace namespace = null;

		if (parent != null) {
			namespace = getParentNamespace(program, parent);
			if (namespace == null) {
				// there was a namespace specified, but not uniquely found, so can't resolve.
				return null;
			}
		}
		SymbolTable symbolTable = program.getSymbolTable();
		List<Symbol> symbols = symbolTable.getLabelOrFunctionSymbols(symbolName, namespace);
		if (symbols.size() == 1) {
			return symbols.get(0).getAddress();
		}
		return null;
	}

	private Namespace getParentNamespace(Program program, SymbolPath path) {
		if (path == null) {
			return null;
		}
		List<Namespace> spaces = NamespaceUtils.getNamespaceByPath(program, null, path.getPath());
		if (spaces.size() == 1) {
			return spaces.get(0);
		}
		return null;
	}

	private Program getProgram() {
		if (programReference != null) {
			return programReference.get();
		}
		return null;
	}
}
