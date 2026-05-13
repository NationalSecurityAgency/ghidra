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

import java.util.*;
import java.util.stream.Collectors;

import ghidra.program.model.listing.Program;

public class Annotation {

	private static final char BS = '\\';
	private static final String SEP = "\\s";
	private static final String ESCAPABLE_CHARS = "{}\"\\";

	private final String[] annotationParts;
	private final String annotationText;

	/**
	 * Constructor
	 * <br>
	 * <b>Note</b>: This constructor assumes that the string starts with 
	 * "{<pre>@</pre>" and ends with '}'
	 * 
	 * @param annotationText the complete annotation text.
	 */
	public Annotation(String annotationText) {
		this.annotationParts = parseAnnotationText(annotationText);
		this.annotationText = annotationText;
	}

	/**
	 * Constructor.  Used for creating a new Annotation from a previously parsed annotation String.
	 *
	 * @param annotationParts The annotation parts.
	 */
	public Annotation(String[] annotationParts) {
		this.annotationParts = annotationParts;
		this.annotationText = buildAnnotationText(annotationParts);
	}

	/**
	 * Deprecated.  Use {@link #Annotation(String)}.
	 * @param annotationText the complete annotation text
	 * @param program ignored
	 */
	@Deprecated
	public Annotation(String annotationText, Program program) {
		this(annotationText);
	}

	public String[] getAnnotationParts() {
		return annotationParts;
	}

	public String getAnnotationText() {
		return annotationText;
	}

	@Override
	public String toString() {
		return annotationText;
	}

	private static String[] parseAnnotationText(String text) {
		String trimmed = text.substring(2, text.length() - 1); // remove "{@" and '}' 
		return parseText(trimmed);
	}

	private static String buildAnnotationText(String[] text) {
		return Arrays.stream(text)
				.map(Annotation::maybeQuote)
				.collect(Collectors.joining(" ", "{@", "}"));
	}

	private static String[] parseText(String text) {
		List<String> parts = new ArrayList<>();
		boolean escape = false;
		boolean quote = false;
		StringBuilder buffy = new StringBuilder();

		for (char c : text.toCharArray()) {
			if (escape) {
				escape = false;
				buffy.append(BS);
				buffy.append(c);
				continue;
			}

			if (c == BS) {
				escape = true;
				continue;
			}

			if (c == '"') {
				String s = buffy.toString();
				if (quote) {
					// end quote; keep the text as a single part
					parts.add(s);
				}
				else {
					// new quote start; split previous unquoted text into parts
					parts.addAll(Arrays.asList(s.split(SEP)));
				}
				buffy.setLength(0);
				quote = !quote;
			}
			else {
				buffy.append(c);
			}
		}

		String s = buffy.toString();
		parts.addAll(Arrays.asList(s.split(SEP)));

		return parts.stream()
				.filter(t -> t.length() > 0)
				.map(t -> removeEscapeChars(t))
				.toArray(String[]::new);
	}

	// remove any backslashes that escape special annotation characters, like '{' and '}'
	private static String removeEscapeChars(String text) {
		boolean escape = false;
		StringBuilder buffy = new StringBuilder();
		for (char c : text.toCharArray()) {
			if (escape) {
				escape = false;
				if (ESCAPABLE_CHARS.indexOf(c) == -1) {
					buffy.append(BS); // restore non-escaping backslash
				}
				buffy.append(c);
				continue;
			}

			if (c == BS) {
				escape = true;
				continue;
			}

			buffy.append(c);
		}

		return buffy.toString();
	}

	private static String maybeQuote(String text) {
		if (needsQuotes(text)) {
			return '"' + escapeAnnotationChars(text) + '"';
		}
		return text;
	}

	private static boolean needsQuotes(String text) {
		for (char c : text.toCharArray()) {
			if (ESCAPABLE_CHARS.indexOf(c) != -1 || Character.isWhitespace(c)) {
				return true;
			}
		}
		return false;
	}

	private static String escapeAnnotationChars(String text) {
		StringBuilder buffy = new StringBuilder();
		for (char c : text.toCharArray()) {
			if (ESCAPABLE_CHARS.indexOf(c) != -1) {
				buffy.append(BS);
			}
			buffy.append(c);
		}

		return buffy.toString();
	}
}
