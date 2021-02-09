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

import java.awt.Color;
import java.util.*;
import java.util.regex.Pattern;

import docking.widgets.fieldpanel.field.AttributedString;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;

/**
 * An annotated string handler that handles annotations that begin with
 * {@link #SUPPORTED_ANNOTATIONS}.  This class expects one string following the annotation
 * text that is the address or a symbol name.  The display text will be that of the symbol that
 * is referred to by the address or symbol name.
 */
public class SymbolAnnotatedStringHandler implements AnnotatedStringHandler {

	private static final String INVALID_SYMBOL_TEXT =
		"@symbol annotation must have a valid " + "symbol name or address";
	private static final String[] SUPPORTED_ANNOTATIONS = { "symbol", "sym" };

	public static String convertAnnotationSymbolToAddress(String[] annotationParts, String rawText,
			Program program) {
		if (annotationParts.length <= 1) {
			return null;
		}

		if (program == null) { // this can happen during merge operations
			return null;
		}

		Address address = program.getAddressFactory().getAddress(annotationParts[1]);
		if (address != null) {
			return null; // nothing to do
		}

		String originalValue = annotationParts[1];
		List<Symbol> symbols = getSymbols(originalValue, program);
		if (symbols.size() != 1) {
			// no unique symbol, so leave it as string name
			return null;
		}

		Address symbolAddress = symbols.get(0).getAddress();
		return rawText.replaceFirst(Pattern.quote(originalValue), symbolAddress.toString());
	}

	@Override
	public AttributedString createAnnotatedString(AttributedString prototypeString, String[] text,
			Program program) {

		// if the text is not of adequate size, then show an error string
		if (text.length <= 1) {
			throw new AnnotationException(INVALID_SYMBOL_TEXT);
		}

		if (program == null) { // this can happen during merge operations
			return createUndecoratedString(prototypeString, text);
		}

		List<Symbol> symbols = getSymbols(text[1], program);

		// check for a symbol of the given name first
		if (symbols.size() >= 1) {
			String symbolText = symbols.get(0).getName();
			return new AttributedString(symbolText, prototypeString.getColor(0),
				prototypeString.getFontMetrics(0), true, prototypeString.getColor(0));
		}

		return new AttributedString("No symbol: " + text[1], Color.RED,
			prototypeString.getFontMetrics(0), false, null);
	}

	private AttributedString createUndecoratedString(AttributedString prototypeString,
			String[] text) {
		StringBuilder buffer = new StringBuilder();
		for (String string : text) {
			buffer.append(string).append(" ");
		}

		return new AttributedString(buffer.toString(), Color.LIGHT_GRAY,
			prototypeString.getFontMetrics(0));
	}

	private static List<Symbol> getSymbols(String rawText, Program program) {
		List<Symbol> list = NamespaceUtils.getSymbols(rawText, program);
		if (!list.isEmpty()) {
			return list;
		}

		// if we get here, then see if the value is an address
		Address address = program.getAddressFactory().getAddress(rawText);
		if (address != null) {
			SymbolTable symbolTable = program.getSymbolTable();
			Symbol symbol = symbolTable.getPrimarySymbol(address);
			if (symbol != null) {
				return Arrays.asList(symbol);
			}
		}

		return Collections.emptyList();
	}

	@Override
	public String[] getSupportedAnnotations() {
		return SUPPORTED_ANNOTATIONS;
	}

	@Override
	public boolean handleMouseClick(String[] annotationParts, Navigatable sourceNavigatable,
			ServiceProvider serviceProvider) {

		String symbolText = annotationParts[1];
		Program program = sourceNavigatable.getProgram();
		List<Symbol> symbols = getSymbols(symbolText, program);

		GoToService goToService = serviceProvider.getService(GoToService.class);

		// try going to the symbol first
		if (!symbols.isEmpty()) {
			Symbol s = symbols.get(0);
			return goToService.goTo(s.getProgramLocation());
		}

		// try going to the address
		Address address = program.getAddressFactory().getAddress(symbolText);
		if (address != null) {
			return goToService.goTo(sourceNavigatable, address);
		}

		Msg.showInfo(getClass(), null, "Invalid symbol text: " + symbolText,
			"Unable to locate a symbol for \"" + symbolText + "\"");

		return false;
	}

	/**
	 * @see ghidra.app.util.viewer.field.AnnotatedStringHandler#getDisplayString()
	 */
	@Override
	public String getDisplayString() {
		return "Symbol";
	}

	/**
	 * @see ghidra.app.util.viewer.field.AnnotatedStringHandler#getPrototypeString()
	 */
	@Override
	public String getPrototypeString() {
		return "{@symbol symbol_address}";
	}

}
