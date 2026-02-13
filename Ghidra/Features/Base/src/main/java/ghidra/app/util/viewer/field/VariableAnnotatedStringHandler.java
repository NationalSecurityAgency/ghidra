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

import docking.widgets.fieldpanel.field.AttributedString;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;

/**
 * An annotated string handler that handles annotations that begin with
 * {@link #SUPPORTED_ANNOTATIONS}.  This class expects one string following the annotation
 * text that is the name of a script.
 */
public class VariableAnnotatedStringHandler implements AnnotatedStringHandler {

	private static final String DEFAULT_ANO = "var";
	private static final String HASH_ANO = DEFAULT_ANO + "_hash";
	private static final String[] SUPPORTED_ANNOTATIONS = { "variable", DEFAULT_ANO, HASH_ANO };

	private static final String INVALID_SYMBOL_TEXT =
		"@" + DEFAULT_ANO + " annotation must have form: <var_sym> [<func_sym>]";


	@Override
	public AttributedString createAnnotatedString(AttributedString prototypeString, String[] text,
			Program program) {
		if (program == null) { // this can happen during merge operations
			final StringBuilder buffer = new StringBuilder();
			for (String string : text) {
				buffer.append(string).append(" ");
			}

			return new AttributedString(buffer.toString(), Palette.LIGHT_GRAY,
				prototypeString.getFontMetrics(0));
		}

		if (text.length != 3) {
			if (text.length == 2) {
				throw new AnnotationException("Function symbol is not optional when rendering.");
			}
			throw new AnnotationException(INVALID_SYMBOL_TEXT);
		}

		final Function func = getFunction(program, text[2]);
		if (func == null) {
			throw new AnnotationException("Could not find function matching \"" + text[2] + "\"");
		}
		final Variable var = getVariable(func, getFilterGenerator(text[0]).apply(text[1]));
		if (var == null) {
			throw new AnnotationException("Could not find variable in function \"" +
					func.getName() + "\" matching \"" + text[1] + "\".");
		}

		return new AttributedString(var.getName(), prototypeString.getColor(0),
				prototypeString.getFontMetrics(0), true, prototypeString.getColor(0));
	}

	@Override
	public String[] modify(String[] text, Program program) {
		if (program == null) { // this can happen during merge operations
			return null;
		}

		Function func = null;
		Variable var = null;
		
		switch (text.length) {
		case 3:
			func = getFunction(program, text[2]);
		case 2:
			if (func == null) {
				return null;
			}
			var = getVariable(func, getFilterGenerator(text[0]).apply(text[1]));
			break;
		default:
			return null;
		}
		
		if (var == null) {
			return null;
		}

		return new String[] {
				HASH_ANO,
				Integer.toUnsignedString(var.hashCode(), 16),
				func.getEntryPoint().toString()
		};
	}

	@Override
	public String[] getSupportedAnnotations() {
		return SUPPORTED_ANNOTATIONS;
	}

	@Override
	public boolean handleMouseClick(String[] annotationParts, Navigatable sourceNavigatable,
			ServiceProvider serviceProvider) {
		final Program program = sourceNavigatable.getProgram();

		if (annotationParts.length != 3) {
			return false;
		}
		final Function func = getFunction(program, annotationParts[2]);
		if (func == null) {
			return false;
		}
		final Variable var = getVariable(func, getFilterGenerator(annotationParts[0]).apply(annotationParts[1]));
		if (var == null) {
			return false;
		}
		Symbol sym = var.getSymbol();
		if (sym == null) {
			sym = func.getSymbol();
		}

		final GoToService goToService = serviceProvider.getService(GoToService.class);
		return goToService.goTo(sym.getProgramLocation());
	}

	@Override
	public String getDisplayString() {
		return "Variable";
	}

	@Override
	public String getPrototypeString() {
		return "{@" + DEFAULT_ANO + " var_sym [func_sym]}";
	}

	@Override
	public String getPrototypeString(String displayText) {
		return "{@" + DEFAULT_ANO + " " + displayText.trim() + "}";
	}

	private static Function getFunction(final Program program, final String name) {
		final FunctionManager func_manager = program.getFunctionManager();

		for (Symbol sym : NamespaceUtils.getSymbols(name, program)) {
			final Function func = func_manager.getFunctionAt(sym.getAddress());
			if (func != null) {
				return func;
			}
		}

		// if we get here, then see if the value is an address
		final Address addr = program.getAddressFactory().getAddress(name);
		if (addr != null) {
			final Function func = func_manager.getFunctionAt(addr);
			if (func != null) {
				return func;
			}
		}

		return null;
	}

	private static Variable getVariable(final Function func, JFunction<Variable, Boolean> name_filter) {
		for (Variable var : func.getAllVariables()) {
			if (name_filter.apply(var)) {
				return var;
			}
		}

		return null;
	}

	/**
	 * Get the correct filter generator for parsing the local variable.
	 *
	 * @param name the name of the annotation
	 * @return the filter generator
	 */
	private static JFunction<String,JFunction<Variable, Boolean>> getFilterGenerator(final String name) {
		switch (name) {
		case HASH_ANO:
			return VariableAnnotatedStringHandler::hashFilterGen;
		default:
			return VariableAnnotatedStringHandler::nameFilterGen;
		}
	}

	private static JFunction<Variable, Boolean> hashFilterGen(String s) {
		try {
			final int hash = Integer.parseUnsignedInt(s, 16);
			return (x) -> x.hashCode() == hash;
		} catch (NumberFormatException e) {
			return (x) -> false;
		}
	}

	private static JFunction<Variable, Boolean> nameFilterGen(String s) {
		return (x) -> x.getName().equals(s);
	}

	private interface JFunction<T, R> extends java.util.function.Function<T, R> {}
}
