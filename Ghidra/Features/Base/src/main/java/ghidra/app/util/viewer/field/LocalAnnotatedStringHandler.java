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

import docking.widgets.fieldpanel.field.AttributedString;
import generic.stl.Pair;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.nav.Navigatable;
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
public class LocalAnnotatedStringHandler implements AnnotatedStringHandler {

	private static final String INVALID_SYMBOL_TEXT =
		"@local annotation must have form: <func_sym> <local_sym> or <func_sym> \" USER\" <local_hash>";
	private static final String[] SUPPORTED_ANNOTATIONS = { "local", "lcl" };

	/* Function and local symbols or addresses cannot contain spaces. */
	private static final String HASH_MARKER_START = " ";

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

		final String[] s = Arrays.copyOfRange(text, 1, text.length);

		final Pair<Function,String[]> func = getFunction(program, s);
		final Pair<Variable,String[]> var = getVariable(func.first, func.second);

		/* Should be no more annotation to consume */
		if (var.second.length != 0) {
			throw new AnnotationException(INVALID_SYMBOL_TEXT);
		}

		return new AttributedString(var.first.getName(), prototypeString.getColor(0),
				prototypeString.getFontMetrics(0), true, prototypeString.getColor(0));
	}

	@Override
	public String[] modify(String[] text, Program program) {
		if (program == null) { // this can happen during merge operations
			return null;
		}

		final String[] s = Arrays.copyOfRange(text, 1, text.length);

		try {
			final Pair<Function,String[]> func = getFunction(program, s);
			final Pair<Variable,String[]> var = getVariable(func.first, func.second);

			/* Should be no more annotation to consume */
			if (var.second.length != 0) {
				return null;
			}

			return new String[] {
					text[0],
					func.first.getEntryPoint().toString(),
					HASH_MARKER_START + "AUTO",
					Integer.toUnsignedString(var.first.hashCode(), 16)
			};
		} catch(AnnotationException e) {
		}
		return null;
	}

	@Override
	public String[] getSupportedAnnotations() {
		return SUPPORTED_ANNOTATIONS;
	}

	@Override
	public boolean handleMouseClick(String[] annotationParts, Navigatable sourceNavigatable,
			ServiceProvider serviceProvider) {
		return false;
	}

	@Override
	public String getDisplayString() {
		return "Local";
	}

	@Override
	public String getPrototypeString() {
		return "{@local function_sym local_sym}";
	}

	@Override
	public String getPrototypeString(String displayText) {
		return "{@local " + displayText.trim() + "}";
	}

	/**
	 * Ensure that a minimum number of elements exist in an array.
	 *
	 * @param s the array to check
	 * @param n the minimum number of elements
	 * @return the new array without the first n elements
	 */
	private static String[] enforceRemaining(String[] s, int n) {
		final int s_len = s.length;
		if (s_len < n) {
			throw new AnnotationException(INVALID_SYMBOL_TEXT);
		}
		return Arrays.copyOfRange(s, n, s_len);
	}

	/**
	 * Parse a function from the annotation text.
	 *
	 * @param program the program the function is a part of
	 * @param text the remaining annotation to parse
	 * @return a pair containing the function and any remaining annotation
	 */
	private static Pair<Function, String[]> getFunction(final Program program, final String[] text) {
		final String[] out = enforceRemaining(text, 1);
		final String search = text[0];

		final FunctionManager func_manager = program.getFunctionManager();

		for (Symbol sym : NamespaceUtils.getSymbols(search, program)) {
			final Function func = func_manager.getFunctionAt(sym.getAddress());
			if (func != null) {
				return new Pair<>(func, out);
			}
		}

		// if we get here, then see if the value is an address
		final Address addr = program.getAddressFactory().getAddress(search);
		if (addr != null) {
			final Function func = func_manager.getFunctionAt(addr);
			if (func != null) {
				return new Pair<>(func, out);
			}
		}

		throw new AnnotationException("Could not find function matching \"" + search + "\"");
	}

	/**
	 * Parse a local variable from the annotation text.
	 *
	 * @param func the function the local variable is a part of
	 * @param text the remaining annotation to parse
	 * @return a pair containing the local variable and any remaining annotation
	 */
	private static Pair<Variable,String[]> getVariable(final Function func, final String[] text)
			throws AnnotationException {
		final Pair<JFunction<String,JFunction<Variable, Boolean>>, String[]> filter_gen =
				getFilterGenerator(text);

		final String[] filter_gen_text = filter_gen.second;
		final String[] out = enforceRemaining(filter_gen_text, 1);
		final String s_var = filter_gen_text[0];
		final JFunction<Variable, Boolean> filter = filter_gen.first.apply(s_var);

		for (Variable var : func.getLocalVariables()) {
			if (filter.apply(var)) {
				return new Pair<>(var, out);
			}
		}

		throw new AnnotationException("Could not find local variable in function \"" +
				func.getName() + "\" matching \"" + s_var + "\".");
	}

	/**
	 * Get the correct filter generator for parsing the local variable.
	 *
	 * @param text the remaining annotation to parse
	 * @return a pair containing the filter generator and any remaining annotation
	 */
	private static Pair<JFunction<String,JFunction<Variable, Boolean>>, String[]>
			getFilterGenerator(final String[] text) {
		if (text.length != 0 && text[0].startsWith(HASH_MARKER_START)) {
			final String[] out = enforceRemaining(text, 1);
			return new Pair<>(LocalAnnotatedStringHandler::hashFilterGen, out);
		}

		return new Pair<>(LocalAnnotatedStringHandler::nameFilterGen, text);
	}

	private static JFunction<Variable, Boolean> hashFilterGen(String s) {
		try {
			final int hash = Integer.parseUnsignedInt(s, 16);
			return (x) -> x.hashCode() == hash;
		} catch (NumberFormatException e) {
			throw new AnnotationException("Could not parse hash \"" +
					s + "\".");
		}
	}

	private static JFunction<Variable, Boolean> nameFilterGen(String s) {
		return (x) -> x.getName().equals(s);
	}

	private interface JFunction<T, R> extends java.util.function.Function<T, R> {}
}
