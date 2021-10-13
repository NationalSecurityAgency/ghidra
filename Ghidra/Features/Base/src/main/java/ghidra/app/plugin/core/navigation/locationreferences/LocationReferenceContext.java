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
package ghidra.app.plugin.core.navigation.locationreferences;

import java.util.*;

import generic.json.Json;
import ghidra.util.HTMLUtilities;

/**
 * A class to hold context representation for {@link LocationReference}s.
 * 
 * @see LocationReferenceContextBuilder
 */
public class LocationReferenceContext {

	private static final String EMBOLDEN_START =
		"<span style=\"background-color: #a3e4d7; color: black;\"><b><font size=4>";
	private static final String EMBOLDEN_END = "</font></b></span>";

	public static final LocationReferenceContext EMPTY_CONTEXT = new LocationReferenceContext();

	private final List<Part> parts;

	/**
	 * A factory method to create a context instance with the given text.  The context created this
	 * way will have no special HTML formatting applied by {@link #getBoldMatchingText()}, as no
	 * matching parts will be defined.
	 * @param text the text
	 * @return the context
	 */
	public static LocationReferenceContext get(String text) {
		return text == null ? EMPTY_CONTEXT : new LocationReferenceContext(text);
	}

	/**
	 * A factory method to provided as a convenience to handle null context objects.
	 * @param context the context to verify is not null
	 * @return the given context or the {@link #EMPTY_CONTEXT} if the given context is null
	 */
	public static LocationReferenceContext get(LocationReferenceContext context) {
		return context == null ? EMPTY_CONTEXT : context;
	}

	/**
	 * Creates an empty context object
	 */
	private LocationReferenceContext() {
		this.parts = List.of(new BasicPart(""));
	}

	/**
	 * Creates a context with the raw and decorated context being the same.
	 * @param context the context; cannot be null
	 */
	private LocationReferenceContext(String context) {
		Objects.requireNonNull(context);
		this.parts = List.of(new BasicPart(context));
	}

	/**
	 * Constructor used to create this context by providing the given text parts
	 * @param parts the parts
	 * @see LocationReferenceContextBuilder
	 */
	LocationReferenceContext(List<Part> parts) {
		this.parts = parts;
	}

	/**
	 * The full plain text of this context.
	 * @return the text
	 */
	public String getPlainText() {
		StringBuilder buffy = new StringBuilder();
		for (Part part : parts) {
			buffy.append(part.getText());
		}
		return buffy.toString();
	}

	/**
	 * Returns HTML text for this context.  Any matching items embedded in the returned string will
	 * be bold.
	 * @return the text
	 */
	public String getBoldMatchingText() {
		StringBuilder buffy = new StringBuilder();
		for (Part part : parts) {
			buffy.append(part.getHtmlText());
		}
		return HTMLUtilities.HTML + buffy.toString();
	}

	/**
	 * Returns any sub-strings of this context's overall text that match client-defined input
	 * 
	 * See the {@link LocationReferenceContextBuilder} for how to define matching text pieces
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

	@Override
	public String toString() {
		return Json.toString(this);
	}

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

		abstract String getText(String start, String end);

		static String fixBreakingSpaces(String s) {
			String updated = s.replaceAll("\\s", "&nbsp;");
			return updated;
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
		String getText(String start, String end) {
			return text; // we don't decorate
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
		String getText(String start, String end) {
			return start + text + end;
		}

		@Override
		String getHtmlText() {
			String escaped = HTMLUtilities.escapeHTML(text);
			String updated = fixBreakingSpaces(escaped);
			return EMBOLDEN_START + updated + EMBOLDEN_END;
		}
	}
}
