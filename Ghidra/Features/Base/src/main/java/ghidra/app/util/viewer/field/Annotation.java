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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import ghidra.program.model.listing.Program;

public class Annotation {

	public static final String ESCAPABLE_CHARS = "{}\"\\";

	private final String[] annotationParts;
	private final String annotationText;

	/**
	 * Constructor
	 * <b>Note</b>: This constructor assumes that the string starts with "{<pre>@</pre>" and ends with '}'
	 * 
	 * @param annotationText The complete annotation text.
	 * text this Annotation can create
	 * @param program the program
	 */
	public Annotation(String annotationText) {
		this.annotationParts = parseAnnotationText(annotationText);
		this.annotationText = annotationText;
	}

	@Deprecated
	public Annotation(String annotationText, Program program) {
		this(annotationText);
	}

	/**
	 * Constructor
	 *
	 * @param annotationParts The annotation parts.
	 * @param program the program
	 */
	public Annotation(String[] annotationParts) {
		this.annotationParts = annotationParts;
		this.annotationText = buildAnnotationText(annotationParts);
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
				.map((t) -> hasEscapeChars(t) ?
						("\"" + addEscapeChars(t) + "\"") : t)
				.collect(Collectors.joining(" ", "{@", "}"));
	}

	private static String[] parseText(String text) {
		List<String> textParts = new ArrayList<>();
		boolean escape = false;
		boolean quote = false;
		StringBuilder buffy = new StringBuilder();

		for (char c: text.toCharArray()) {
			if (escape) {
				escape = false;
				buffy.append('\\');
				buffy.append(c);
			} else {
				if (c == '\\') {
					escape = true;
				} else if (c == '\"') {
					String s = buffy.toString();
					if (quote) {
						textParts.add(s);
					} else {
						textParts.addAll(Arrays.asList(s.split("\\s")));
					}
					buffy.setLength(0);
					quote = !quote;
				} else {
					buffy.append(c);
				}
			}
		}
		textParts.addAll(Arrays.asList(buffy.toString().split("\\s")));

		return textParts.stream()
				.filter((t) -> t.length() > 0)
				.map((t) -> removeEscapeChars(t))
				.toArray(String[]::new);
	}

	// remove any backslashes that escape special annotation characters, like '{' and '}'
	private static String removeEscapeChars(String text) {
		boolean escape = false;
		StringBuilder buffy = new StringBuilder();

		for (char c: text.toCharArray()) {
			if (escape) {
				escape = false;
				if (ESCAPABLE_CHARS.indexOf(c) == -1) {
					buffy.append('\\');
				}
				buffy.append(c);
			} else {
				if (c == '\\') {
					escape = true;
				} else {
					buffy.append(c);
				}
			}
		}

		return buffy.toString();
	}

	private static boolean hasEscapeChars(String text) {
		for (char c: text.toCharArray()) {
			if (ESCAPABLE_CHARS.indexOf(c) != -1 || Character.isWhitespace(c)) {
				return true;
			}
		}
		return false;
	}

	private static String addEscapeChars(String text) {
		StringBuilder buffy = new StringBuilder();

		for (char c: text.toCharArray()) {
			if (ESCAPABLE_CHARS.indexOf(c) != -1) {
				buffy.append('\\');
			}
			buffy.append(c);
		}

		return buffy.toString();
	}
}
