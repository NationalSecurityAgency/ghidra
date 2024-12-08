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

import docking.widgets.fieldpanel.field.AttributedString;
import ghidra.app.nav.Navigatable;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;

public class Annotation {

	public static final String ESCAPABLE_CHARS = "{}\"\\";

	private static List<AnnotatedStringHandler> ANNOTATED_STRING_HANDLERS;
	private static Map<String, AnnotatedStringHandler> ANNOTATED_STRING_MAP;

	private String annotationText;
	private String[] annotationParts;
	private AnnotatedStringHandler annotatedStringHandler;
	private AttributedString displayString;

	public static List<AnnotatedStringHandler> getAnnotatedStringHandlers() {
		if (ANNOTATED_STRING_HANDLERS == null) {
			ANNOTATED_STRING_HANDLERS = getSupportedAnnotationHandlers();
		}
		return ANNOTATED_STRING_HANDLERS;
	}

	private static Map<String, AnnotatedStringHandler> getAnnotatedStringHandlerMap() {
		if (ANNOTATED_STRING_MAP == null) { // lazy init due to our use of ClassSearcher
			ANNOTATED_STRING_MAP = createAnnotatedStringHandlerMap();
		}
		return ANNOTATED_STRING_MAP;
	}

	private static Map<String, AnnotatedStringHandler> createAnnotatedStringHandlerMap() {
		Map<String, AnnotatedStringHandler> map = new HashMap<>();
		for (AnnotatedStringHandler instance : getAnnotatedStringHandlers()) {
			String[] supportedAnnotations = instance.getSupportedAnnotations();
			for (String supportedAnnotation : supportedAnnotations) {
				map.put(supportedAnnotation, instance);
			}
		}
		return Collections.unmodifiableMap(map);
	}

	// locates AnnotatedStringHandler implementations to handle annotations
	private static List<AnnotatedStringHandler> getSupportedAnnotationHandlers() {
		List<AnnotatedStringHandler> list = new ArrayList<>();
		for (AnnotatedStringHandler h : ClassSearcher.getInstances(AnnotatedStringHandler.class)) {
			if (h.getSupportedAnnotations().length != 0) {
				list.add(h);
			}
		}
		return Collections.unmodifiableList(list);
	}

	/**
	 * Constructor
	 * <b>Note</b>: This constructor assumes that the string starts with "{<pre>@</pre>" and ends with '}'
	 * 
	 * @param annotationText The complete annotation text.
	 * @param prototypeString An AttributedString that provides the attributes for the display
	 * text this Annotation can create
	 * @param program the program
	 */
	public Annotation(String annotationText, AttributedString prototypeString, Program program) {

		this.annotationText = annotationText;
		annotationParts = parseAnnotationText(annotationText);

		annotatedStringHandler = getHandler(annotationParts);

		try {
			displayString = annotatedStringHandler.createAnnotatedString(prototypeString,
				annotationParts, program);
		}
		catch (AnnotationException ae) {
			// uh-oh
			annotatedStringHandler =
				new InvalidAnnotatedStringHandler("Annotation Exception: " + ae.getMessage());
			displayString = annotatedStringHandler.createAnnotatedString(prototypeString,
				annotationParts, program);
		}
	}

	private AnnotatedStringHandler getHandler(String[] annotationPieces) {

		if (annotationPieces.length <= 1) {
			return new InvalidAnnotatedStringHandler(
				"Invalid annotation format." + " Expected at least two strings.");
		}

		// the first part is the annotation (@xxx)
		String keyword = annotationPieces[0];
		AnnotatedStringHandler handler = getAnnotatedStringHandlerMap().get(keyword);

		if (handler == null) {
			return new InvalidAnnotatedStringHandler("Invalid annotation keyword: " + keyword);
		}
		return handler;
	}

	String[] getAnnotationParts() {
		return annotationParts;
	}

	AnnotatedStringHandler getHandler() {
		return annotatedStringHandler;
	}

	public AttributedString getDisplayString() {
		return displayString;
	}

	/**
	 * Called when a mouse click occurs on a FieldElement containing this Annotation.
	 * 
	 * @param sourceNavigatable The source navigatable associated with the mouse click.
	 * @param serviceProvider The service provider to be used when creating
	 * {@link AnnotatedStringHandler} instances.
	 * @return true if the handler desires to handle the mouse click.
	 */
	public boolean handleMouseClick(Navigatable sourceNavigatable,
			ServiceProvider serviceProvider) {
		return annotatedStringHandler.handleMouseClick(annotationParts, sourceNavigatable,
			serviceProvider);
	}

	public String getAnnotationText() {
		return annotationText;
	}

	@Override
	public String toString() {
		return annotationText;
	}

	/*package*/ static Set<String> getAnnotationNames() {
		return Collections.unmodifiableSet(getAnnotatedStringHandlerMap().keySet());
	}

	private String[] parseAnnotationText(String text) {

		String trimmed = text.substring(2, text.length() - 1); // remove "{@" and '}' 
		List<String> tokens = new ArrayList<>();
		List<TextPart> parts = parseText(trimmed);
		for (TextPart part : parts) {
			part.grabTokens(tokens);
		}

		return tokens.toArray(new String[tokens.size()]);
	}

	private List<TextPart> parseText(String text) {

		List<TextPart> textParts = new ArrayList<>();
		boolean escaped = false;
		boolean inQuote = false;
		int partStart = 0;
		int n = text.length();
		for (int i = 0; i < n; i++) {

			boolean wasEscaped = escaped;
			escaped = false;
			char prev = '\0';
			if (i != 0 && !wasEscaped) {
				prev = text.charAt(i - 1);
			}

			char c = text.charAt(i);
			if (prev == '\\') {
				if (Annotation.ESCAPABLE_CHARS.indexOf(c) != -1) {
					escaped = true;
					continue;
				}
			}

			if (c == '"') {
				if (inQuote) {
					// end quote
					String s = text.substring(partStart, i + 1); // keep the quote
					textParts.add(new QuotedTextPart(s));
					partStart = i + 1;
				}
				else {
					// end previous word; start quote
					if (i != 0) {
						String s = text.substring(partStart, i);
						textParts.add(new TextPart(s));
						partStart = i;
					}
				}
				inQuote = !inQuote;
			}
		}

		if (partStart < n) { // grab trailing text
			String s = text.substring(partStart, n);
			textParts.add(new TextPart(s));
		}

		return textParts;
	}

	// remove any backslashes that escape special annotation characters, like '{' and '}'
	private static String removeEscapeChars(String text) {
		boolean escaped = false;
		StringBuilder buffy = new StringBuilder();
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			boolean wasEscaped = escaped;
			escaped = false;
			if (c != '\\') {
				buffy.append(c);
				continue;
			}

			char next = '\0';
			if (i != text.length() - 1 && !wasEscaped) {
				next = text.charAt(i + 1);
			}

			if (ESCAPABLE_CHARS.indexOf(next) != -1) {
				escaped = true;
				continue;
			}
			buffy.append(c);
		}

		return buffy.toString();
	}

	/**
	 * A simple class to hold text and extract tokens 
	 */
	private class TextPart {

		protected String text;

		TextPart(String text) {
			this.text = text;
		}

		public void grabTokens(List<String> tokens) {
			String escaped = removeEscapeChars(text);
			String[] strings = escaped.split("\\s");
			for (String string : strings) {
				// 0 length strings can happen when 'content' begins with a space
				if (string.length() > 0) {
					tokens.add(string);
				}
			}
		}

		@Override
		public String toString() {
			return text;
		}
	}

	private class QuotedTextPart extends TextPart {
		QuotedTextPart(String text) {
			super(text);
		}

		@Override
		public void grabTokens(List<String> tokens) {
			String unquoted = text.substring(1, text.length() - 1);
			String escaped = removeEscapeChars(unquoted);
			tokens.add(escaped); // all quoted text is a 'token'
		}
	}

}
