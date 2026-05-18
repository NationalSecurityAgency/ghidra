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
package ghidra.app.util.viewer.field;

import java.util.Arrays;
import java.util.stream.Collectors;

import docking.widgets.fieldpanel.field.AttributedString;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;

/**
 * Provides support for local function variable annotations.
 * <p>
 * This allows users to reference function variables in comments without having to change the 
 * comment text when the variable is renamed.  Users can enter the annotation using the variable's
 * name:
 * <pre>{@code
 * 	{@variable local_8}
 *		 		
 *	 or
 *		 		
 *	{@variable coolVariable SomeFunction}
 * }</pre>
 * The user annotation will be converted to use address information:
 * <pre>{@code
 * 	{@variable Stack[0xa] FUN_1234eaea}
 * }</pre>
 */
public class VariableAnnotatedStringHandler implements AnnotatedStringHandler {

	private static final String[] SUPPORTED_ANNOTATIONS = { "variable", "var" };

	@Override
	public String[] getSupportedAnnotations() {
		return SUPPORTED_ANNOTATIONS;
	}

	@Override
	public String getDisplayString() {
		return "Variable";
	}

	@Override
	public String getPrototypeString() {
		return "{@variable variable_name}";
	}

	@Override
	public String getPrototypeString(String displayText) {
		return "{@variable " + displayText.trim() + "}";
	}

	@Override
	public AttributedString createAnnotatedString(AttributedString prototypeString, String[] text,
			Program program) throws AnnotationException {

		/*
		 	We expect to be handed annotation text that was updated via a previous call to modify().
		 	The annotation will be of the form {@variable variable_address function_address}
		 */
		if (text.length != 3) {
			throw new AnnotationException(
				"@variable annotation must have a variable address and a function name");
		}

		if (program == null) { // this can happen during merge operations
			return createPlaceholderString(prototypeString, text);
		}

		String entry = text[2];
		Function function = getFunctionAt(program, entry);
		if (function == null) {
			throw new AnnotationException("Could not find function \"" + entry + "\"");
		}

		String address = text[1];
		Variable var = getVariable(function, address);
		if (var == null) {
			String functionName = function.getName();
			throw new AnnotationException(
				"Could not find variable at address %s in function %s".formatted(functionName,
					address));
		}

		return new AttributedString(var.getName(), prototypeString.getColor(0),
			prototypeString.getFontMetrics(0), true, prototypeString.getColor(0));
	}

	private AttributedString createPlaceholderString(AttributedString prototypeString,
			String[] text) {
		String joined = Arrays.stream(text).collect(Collectors.joining(" "));
		return new AttributedString(joined, Palette.LIGHT_GRAY,
			prototypeString.getFontMetrics(0));
	}

	private Function getFunction(Program program, String value) {
		FunctionManager manager = program.getFunctionManager();
		for (Symbol s : NamespaceUtils.getSymbols(value, program)) {
			Address addr = s.getAddress();
			Function function = manager.getFunctionAt(addr);
			if (function != null) {
				return function;
			}
		}

		// if we get here, then see if the value is an address
		return getFunctionAt(program, value);
	}

	private Function getFunctionAt(Program program, String address) {
		FunctionManager manager = program.getFunctionManager();
		AddressFactory af = program.getAddressFactory();
		Address addr = af.getAddress(address);
		if (addr != null) {
			Function function = manager.getFunctionAt(addr);
			if (function != null) {
				return function;
			}
		}

		return null;
	}

	/**
	 * Update the annotation to convert names to addresses.
	 * @param text the array of annotation parts to modify
	 * @param program the program
	 * @param addr address of the annotation in the program
	 * @return the modified array; null otherwise
	 */
	@Override
	public String[] modify(String[] text, Program program, Address addr) {
		if (program == null) { // this can happen during merge operations
			return null;
		}

		Function function = null;
		switch (text.length) {
			case 3:
				function = getFunction(program, text[2]);
				break;
			case 2:
				function = program.getFunctionManager().getFunctionContaining(addr);
				break;
			default:
				return null;
		}

		if (function == null) {
			return null;
		}

		String value = text[1]; // value is a variable name or address
		VariableMatcher matcher = createVariableMatcher(program, value);
		Variable var = findVariable(function, matcher);
		if (var == null) {
			return null;
		}

		return new String[] {
			"variable",
			var.getMinAddress().toString(),
			function.getEntryPoint().toString()
		};
	}

	private VariableMatcher createVariableMatcher(Program p, String value) {

		Address addr = toAddress(p, value);
		if (addr != null) {
			return new AddressMatcher(addr);
		}

		return new NameMatcher(value);
	}

	@Override
	public boolean handleMouseClick(String[] text, Navigatable sourceNavigatable,
			ServiceProvider serviceProvider) {

		/*
		 	We expect to be handed annotation text that was updated via a previous call to modify().
		 	The annotation will be of the form {@variable variable_address function_address}
		 */
		if (text.length != 3) {
			return false;
		}

		Program program = sourceNavigatable.getProgram();
		Function function = getFunction(program, text[2]);
		if (function == null) {
			return false;
		}

		String address = text[1];
		Variable var = getVariable(function, address);
		if (var == null) {
			return false;
		}

		Symbol symbol = var.getSymbol();
		if (symbol == null) {
			symbol = function.getSymbol();
		}

		GoToService goToService = serviceProvider.getService(GoToService.class);
		if (goToService == null) {
			Msg.debug(this, "GoToService not installed");
			return false;
		}

		return goToService.goTo(symbol.getProgramLocation());
	}

	private Variable getVariable(Function function, String addressString) {
		Program p = function.getProgram();
		Address addr = toAddress(p, addressString);
		VariableMatcher matcher = new AddressMatcher(addr);
		return findVariable(function, matcher);
	}

	private static Variable findVariable(Function function, VariableMatcher matcher) {
		for (Variable var : function.getAllVariables()) {
			if (matcher.matches(var)) {
				return var;
			}
		}

		return null;
	}

	private static Address toAddress(Program p, String s) {
		AddressFactory af = p.getAddressFactory();
		return af.getAddress(s);
	}

	private static interface VariableMatcher {
		public boolean matches(Variable v);
	}

	private static class NameMatcher implements VariableMatcher {

		private String name;

		NameMatcher(String name) {
			this.name = name;
		}

		@Override
		public boolean matches(Variable v) {
			return v.getName().equals(name);
		}
	}

	private static class AddressMatcher implements VariableMatcher {

		private Address addr;

		AddressMatcher(Address addr) {
			this.addr = addr;
		}

		@Override
		public boolean matches(Variable v) {
			return v.getMinAddress().equals(addr);
		}
	}
}
