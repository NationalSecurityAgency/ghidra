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
package ghidra.app.plugin.core.analysis.rust.demangler;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import generic.json.Json;
import ghidra.app.util.SymbolPathParser;
import ghidra.app.util.demangler.*;

/** Parses a demangled rust string */
public class RustDemanglerParser {

	private static final char NULL_CHAR = '\u0000';

	private String mangledSource;
	private String demangledSource;

	/**
	 * Parses the given demangled string and creates a {@link DemangledObject}
	 *
	 * @param mangled the original mangled text
	 * @param demangled the demangled text
	 * @return the demangled object
	 * @throws RuntimeException if there is an unexpected error parsing
	 */
	public DemangledObject parse(String mangled, String demangled) throws RuntimeException {

		this.mangledSource = mangled;
		this.demangledSource = demangled;

		return parseNext(demangled);
	}

	private String removeBadSpaces(String text) {
		CondensedString condensedString = new CondensedString(text);
		return condensedString.getCondensedText();
	}

	private void setNameAndNamespace(DemangledObject object, String name) {
		List<String> names = SymbolPathParser.parse(name, false);
		DemangledType namespace = null;
		if (names.size() > 1) {
			namespace = convertToNamespaces(names.subList(0, names.size() - 1));
		}

		String objectName = names.get(names.size() - 1);

		object.setName(objectName);
		object.setNamespace(namespace);
	}

	private DemangledObject parseNext(String demangled) {
		String nameString = removeBadSpaces(demangled).trim();
		DemangledFunction variable =
			new DemangledFunction(mangledSource, demangledSource, (String) null);
		setNameAndNamespace(variable, nameString);
		return variable;
	}

	/**
	 * Converts the list of names into a namespace demangled type.
	 * Given names = { "A", "B", "C" }, which represents "A::B::C".
	 * The following will be created {@literal "Namespace{A}->Namespace{B}->Namespace{C}"}
	 * and Namespace{C} will be returned.
	 *
	 * <p>This method will also escape spaces separators inside of templates
	 * (see {@link #removeBadSpaces(String)}).
	 *
	 * @param names the names to convert
	 * @return the newly created type
	 */
	private DemangledType convertToNamespaces(List<String> names) {
		if (names.isEmpty()) {
			return null;
		}
		int index = names.size() - 1;
		String rawName = names.get(index);
		String escapedName = removeBadSpaces(rawName);
		DemangledType myNamespace = new DemangledType(mangledSource, demangledSource, escapedName);

		DemangledType namespace = myNamespace;
		while (--index >= 0) {
			rawName = names.get(index);
			escapedName = removeBadSpaces(rawName);
			DemangledType parentNamespace =
				new DemangledType(mangledSource, demangledSource, escapedName);
			namespace.setNamespace(parentNamespace);
			namespace = parentNamespace;
		}
		return myNamespace;
	}

	/**
	 * A class to handle whitespace manipulation within demangled strings.  This class will
	 * remove bad spaces, which is all whitespace that is not needed to separate distinct objects
	 * inside of a demangled string.
	 *
	 * <p>Generally, this class removes spaces within templates and parameter lists.   It will
	 * remove some spaces, while converting some to underscores.
	 */
	private class CondensedString {

		@SuppressWarnings("unused") // used by toString()
		private String sourceText;
		private String condensedText;
		private List<Part> parts = new ArrayList<>();

		CondensedString(String input) {
			this.sourceText = input;
			this.condensedText = convertGenericSpace(input);
		}

		private String convertGenericSpace(String name) {

			int depth = 0;
			char last = NULL_CHAR;
			for (int i = 0; i < name.length(); ++i) {

				Part part = new Part();
				parts.add(part);
				char ch = name.charAt(i);
				part.original = Character.toString(ch);
				part.condensed = part.original; // default case
				if (ch == '<' || ch == '(') {
					++depth;
				}
				else if ((ch == '>' || ch == ')') && depth != 0) {
					--depth;
				}

				if (depth > 0 && ch == ' ') {
					char next = (i + 1) < name.length() ? name.charAt(i + 1) : NULL_CHAR;
					if (isSurroundedByCharacters(last, next)) {
						// separate words with a value so they don't run together; drop the other spaces
						part.condensed = "_";
					}
					else {
						part.condensed = "";
					}
				}

				last = ch;
			}

			return parts.stream().map(p -> p.condensed).collect(Collectors.joining()).trim();
		}

		private boolean isSurroundedByCharacters(char last, char next) {
			if (last == NULL_CHAR || next == NULL_CHAR) {
				return false;
			}
			return Character.isLetterOrDigit(last) && Character.isLetterOrDigit(next);
		}

		/**
		 * Returns the original string value that has been 'condensed', which means to remove
		 * internal spaces
		 * @return the condensed string
		 */
		String getCondensedText() {
			return condensedText;
		}

		@Override
		public String toString() {
			return Json.toString(this);
		}

		private class Part {
			String original;
			String condensed = "";

			@Override
			public String toString() {
				return Json.toString(this);
			}
		}
	}
}
