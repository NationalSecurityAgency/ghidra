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
package docking.widgets.search;

import java.util.*;

import docking.widgets.SearchLocation;
import generic.json.Json;
import ghidra.util.HTMLUtilities;

/**
 * A class to hold context representation for {@link SearchLocation}s.
 *
 * @see SearchLocationContextBuilder
 */
public class SearchLocationContext implements Comparable<SearchLocationContext> {

	private static final String EMBOLDEN_START =
		"<span style=\"background-color: #a3e4d7; color: black;\"><b><font size=4>";
	private static final String EMBOLDEN_END = "</font></b></span>";

	public static final SearchLocationContext EMPTY_CONTEXT = new SearchLocationContext();

	private final List<Part> parts;
	private int lineNumber = -1;

	/**
	 * A factory method to create a context instance with the given text.  The context created this
	 * way will have no special HTML formatting applied by {@link #getBoldMatchingText()}, as no
	 * matching parts will be defined.
	 * @param text the text
	 * @return the context
	 */
	public static SearchLocationContext get(String text) {
		return text == null ? EMPTY_CONTEXT : new SearchLocationContext(text);
	}

	/**
	 * A factory method to provided as a convenience to handle null context objects.
	 * @param context the context to verify is not null
	 * @return the given context or the {@link #EMPTY_CONTEXT} if the given context is null
	 */
	public static SearchLocationContext get(SearchLocationContext context) {
		return context == null ? EMPTY_CONTEXT : context;
	}

	/**
	 * Creates an empty context object
	 */
	private SearchLocationContext() {
		this.parts = List.of(new BasicPart(""));
	}

	/**
	 * Creates a context with the raw and decorated context being the same.
	 * @param context the context; cannot be null
	 */
	private SearchLocationContext(String context) {
		Objects.requireNonNull(context);
		this.parts = List.of(new BasicPart(context));
	}

	/**
	 * Constructor used to create this context by providing the given text parts
	 * @param parts the parts
	 * @see SearchLocationContextBuilder
	 */
	SearchLocationContext(List<Part> parts) {
		this.parts = parts;
	}

	SearchLocationContext(List<Part> parts, int lineNumber) {
		this.parts = parts;
		this.lineNumber = lineNumber;
	}

	/**
	 * The full plain text of this context. Any non-negative line number will be prepended to the 
	 * text.
	 * @return the text
	 */
	public String getPlainText() {
		return getPlainText(true);
	}

	/**
	 * Returns the plain text of this context, without html markup. 
	 * 
	 * @param includeLineNumber if true, any non-negative line number will be prepended to the text. 
	 * @return the text
	 */
	public String getPlainText(boolean includeLineNumber) {

		String lnText = "";
		if (includeLineNumber) {
			lnText = getLineNumberText(false);
		}

		StringBuilder buffy = new StringBuilder(lnText);
		for (Part part : parts) {
			buffy.append(part.getText());
		}
		return buffy.toString();
	}

	/**
	 * Returns text that is helpful for debugging, such as printing to a console.
	 * @return the text
	 */
	public String getDebugText() {
		String lnText = getLineNumberText(false);
		StringBuilder buffy = new StringBuilder(lnText);
		for (Part part : parts) {
			buffy.append(part.getDebugText());
		}
		return buffy.toString();
	}

	private String getLineNumberText(boolean isHtml) {
		if (lineNumber < 0) {
			return "";
		}

		// use a non-breaking space for html so lines do not get wrapped
		String space = isHtml ? HTMLUtilities.HTML_SPACE : " ";
		return lineNumber + ":" + space;
	}

	/**
	 * Returns HTML text for this context.  Any matching items embedded in the returned string will 
	 * be bold.  Any non-negative line number will be prepended to the text.
	 * @return the text
	 */
	public String getBoldMatchingText() {
		String lnText = getLineNumberText(true);
		StringBuilder buffy = new StringBuilder(lnText);
		for (Part part : parts) {
			buffy.append(part.getHtmlText());
		}
		return HTMLUtilities.HTML + buffy.toString();
	}

	/**
	 * Returns HTML text for this context.  Any matching items embedded in the returned string will 
	 * be bold.
	 * 
	 * @param includeLineNumber if true, any non-negative line number will be prepended to the text.
	 * @return the text
	 */
	public String getBoldMatchingText(boolean includeLineNumber) {

		String lnText = "";
		if (includeLineNumber) {
			lnText = getLineNumberText(false);
		}

		StringBuilder buffy = new StringBuilder(lnText);
		for (Part part : parts) {
			buffy.append(part.getHtmlText());
		}
		return HTMLUtilities.HTML + buffy.toString();
	}

	/**
	 * Returns any sub-strings of this context's overall text that match client-defined input
	 *
	 * See the {@link SearchLocationContextBuilder} for how to define matching text pieces
	 * @return the matching strings
	 */
	public List<String> getMatches() {
		List<String> matches = new ArrayList<>();
		for (Part part : parts) {
			if (part instanceof MatchPart) {
				matches.add(part.getText());
			}
		}
		return matches;
	}

	/**
	 * Returns the line number or -1 if the value has not been set.
	 * @return the line number
	 */
	public int getLineNumber() {
		return lineNumber;
	}

	@Override
	public String toString() {
		return getPlainText();
	}

	@Override
	public int compareTo(SearchLocationContext other) {

		// Use line numbers when both clients have them, as string integer comparisons do not 
		// naturally sort by integer value.
		int l1 = getLineNumber();
		int l2 = other.getLineNumber();
		int result = Integer.compare(l1, l2);
		if (result != 0) {
			return result;
		}

		// Note: the debug text will call out the portion of the line that matches.  For 
		// multiple matches on the same line, we will have multiple rows.   In that case, 
		// we need the match markup to help sort those lines.
		String t1 = getDebugText();
		String t2 = other.getDebugText();
		return t1.compareTo(t2);
	}

	@Override
	public int hashCode() {
		return Objects.hash(lineNumber, parts);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SearchLocationContext other = (SearchLocationContext) obj;
		return lineNumber == other.lineNumber && Objects.equals(parts, other.parts);
	}

//=================================================================================================
// Inner Classes
//=================================================================================================	

	/**
	 * A class that represents one or more characters within the full text of this context class
	 */
	static abstract class Part {

		protected String text;

		Part(String text) {
			this.text = text;
		}

		String getText() {
			return text;
		}

		abstract String getHtmlText();

		abstract String getDebugText();

		static String fixBreakingSpaces(String s) {
			String updated = s.replaceAll("\\s", HTMLUtilities.HTML_SPACE);
			return updated;
		}

		@Override
		public int hashCode() {
			return Objects.hash(text);
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			Part other = (Part) obj;
			return Objects.equals(text, other.text);
		}

		@Override
		public String toString() {
			return Json.toString(this);
		}
	}

	/**
	 * A basic string part that has no decoration
	 */
	static class BasicPart extends Part {

		BasicPart(String text) {
			super(text);
		}

		@Override
		String getDebugText() {
			return text;
		}

		@Override
		String getHtmlText() {
			String escaped = HTMLUtilities.escapeHTML(text);
			String updated = fixBreakingSpaces(escaped);
			return updated;
		}
	}

	/**
	 * A string part of the overall text of this context that matches client-defined text
	 */
	static class MatchPart extends Part {

		MatchPart(String text) {
			super(text);
		}

		@Override
		String getDebugText() {
			return " [[ " + text + " ]] ";
		}

		@Override
		String getHtmlText() {
			String escaped = HTMLUtilities.escapeHTML(text);
			String updated = fixBreakingSpaces(escaped);
			return EMBOLDEN_START + updated + EMBOLDEN_END;
		}
	}
}
