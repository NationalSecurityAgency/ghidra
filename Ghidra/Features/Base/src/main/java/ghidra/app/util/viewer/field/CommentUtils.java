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

import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.fieldpanel.field.*;
import generic.theme.GThemeDefaults.Colors;
import generic.theme.Gui;
import ghidra.program.model.listing.Program;
import ghidra.util.StringUtilities;
import ghidra.util.WordLocation;

public class CommentUtils {

	// looks like: {@sym|symbol|...
	private static final Pattern ANNOTATION_START_PATTERN = createAnnotationStartPattern();

	/**
	 * Makes adjustments as necessary to any annotations in the given text.
	 * 
	 * @param rawCommentText the text to be updated
	 * @param program the program associated with the comment
	 * @return the updated string
	 */
	public static String fixupAnnotations(String rawCommentText, Program program) {

		if (rawCommentText == null) {
			return null;
		}

		AttributedString prototype = createPrototype();

		// this function will take any given Symbol annotations and change the text, replacing
		// the symbol name with the address of the symbol
		Function<Annotation, Annotation> symbolFixer = annotation -> {

			AnnotatedStringHandler handler = annotation.getHandler();
			if (!(handler instanceof SymbolAnnotatedStringHandler)) {
				return annotation; // nothing to change
			}

			String rawText = annotation.getAnnotationText();
			String[] annotationParts = annotation.getAnnotationParts();
			String updatedText = SymbolAnnotatedStringHandler.convertAnnotationSymbolToAddress(
				annotationParts, rawText, program);
			if (updatedText == null) {
				return annotation; // nothing to change
			}

			return new Annotation(updatedText, prototype, program);
		};

		StringBuilder buffy = new StringBuilder();
		List<CommentPart> parts =
			doParseTextIntoTextAndAnnotations(rawCommentText, symbolFixer, program, prototype);
		for (CommentPart part : parts) {
			buffy.append(part.getRawText());
		}
		return buffy.toString();
	}

	private static AttributedString createPrototype() {
		Font dummyFont = Gui.getFont("font.monospaced");
		@SuppressWarnings("deprecation")
		FontMetrics fontMetrics = Toolkit.getDefaultToolkit().getFontMetrics(dummyFont);
		return new AttributedString("", Colors.FOREGROUND, fontMetrics);
	}

	/**
	 * Returns the display string for the given raw annotation text.  Annotations are 
	 * encoded strings that fit this pattern: <code>{@literal {@name text}}</code>.  This method
	 * will parse the given text, converting any annotations into their display version.
	 * 
	 * @param rawCommentText text that may include annotations
	 * @param program the program
	 * @return the display string
	 */
	public static String getDisplayString(String rawCommentText, Program program) {

		// Posterity: this code used to duplicate the algorithm of the method we now call, 
		//            but seemed unnecessary.  Refer to the history if needed.
		AttributedString prototype = createPrototype();
		FieldElement element = parseTextForAnnotations(rawCommentText, program, prototype, 0);
		String displayText = element.getText();
		return displayText;
	}

	/**
	 * Parses the given text looking for annotations. 
	 *  
	 * @param text The text to parse.
	 * @param program the program from which to get information
	 * @param prototypeString The reference string used to determine the attributes of any 
	 *         newly created AttributedString.
	 * @param row the row of the newly created FieldElement
	 * @return A field element containing {@link AttributedString}s
	 */
	public static FieldElement parseTextForAnnotations(String text, Program program,
			AttributedString prototypeString, int row) {

		Function<Annotation, Annotation> noFixing = Function.identity();
		return doParseTextForAnnotations(text, noFixing, program, prototypeString, row);
	}

	/**
	 * Sanitizes the given text, removing or replacing illegal characters.
	 * <p>
	 * Each illegal character is handled as follows:
	 * <ul>
	 *   <li>null character (\0) -> remove</li>
	 * </ul>
	 * 
	 * @param text The text to sanitize
	 * @return The sanitized text, or null if the given text was null
	 */
	public static String sanitize(String text) {
		if (text == null) {
			return null;
		}
		return text.replaceAll("\0", "");
	}

	/**
	 * Parses the given text looking for annotations. 
	 *  
	 * @param text The text to parse
	 * @param fixerUpper a function that will take an annotation and optionally create a new 
	 *        one.  This allows clients to use the annotations to change the text as needed
	 * @param program the program from which to get information
	 * @param prototype The reference string used to determine the attributes of any 
	 *         newly created AttributedString.
	 * @param row the row of the newly created FieldElement
	 * @return A field element containing {@link AttributedString}s
	 */
	private static FieldElement doParseTextForAnnotations(String text,
			Function<Annotation, Annotation> fixerUpper, Program program,
			AttributedString prototype, int row) {

		// tabs are converted here instead of the GUI dialogs now
		text = StringUtilities.convertTabsToSpaces(text);

		int column = 0;
		List<CommentPart> parts =
			doParseTextIntoTextAndAnnotations(text, fixerUpper, program, prototype);
		List<FieldElement> fields = new ArrayList<>();
		for (CommentPart part : parts) {
			fields.add(part.createElement(row, column));
			column += part.getDisplayText().length();
		}

		return new CompositeFieldElement(fields.toArray(new FieldElement[fields.size()]));
	}

	/**
	 * Split the given text into parts where the returned list contains either a String or 
	 * an Annotation
	 * 
	 * @param text the text to parse
	 * @param fixerUpper a function that is given a chance to convert an Annotation into a new one
	 * @param program the program
	 * @param prototype the prototype string that contains decoration attributes
	 * @return a list that contains a mixture String or an Annotation entries
	 */
	private static List<CommentPart> doParseTextIntoTextAndAnnotations(String text,
			Function<Annotation, Annotation> fixerUpper, Program program,
			AttributedString prototype) {

		List<CommentPart> results = new ArrayList<>();

		List<WordLocation> annotations = getCommentAnnotations(text);
		if (annotations.isEmpty()) {
			results.add(new StringCommentPart(text, prototype));
			return results;
		}

		// split the text into pieces of normal text and annotated
		int offset = 0;
		for (WordLocation word : annotations) {

			int start = word.getStart();
			if (offset != start) {
				// text between annotations
				String preceeding = text.substring(offset, start);
				results.add(new StringCommentPart(preceeding, prototype));
			}

			String annotationText = word.getWord();
			Annotation annotation = new Annotation(annotationText, prototype, program);
			annotation = fixerUpper.apply(annotation);
			results.add(new AnnotationCommentPart(annotationText, annotation));

			offset = start + annotationText.length();
		}

		if (offset != text.length()) { // trailing text
			String trailing = text.substring(offset);
			results.add(new StringCommentPart(trailing, prototype));
		}

		return results;
	}

	/*package*/ static List<WordLocation> getCommentAnnotations(String comment) {

		List<WordLocation> starts = new ArrayList<>();
		Matcher matcher = ANNOTATION_START_PATTERN.matcher(comment);
		while (matcher.find()) {
			int position = matcher.start();
			String text = matcher.group();
			starts.add(new WordLocation(comment, text, position));
		}

		List<WordLocation> results = new ArrayList<>();

		for (WordLocation word : starts) {
			int start = word.getStart();
			int offset = start + word.getWord().length();
			int end = findAnnotationEnd(comment, offset);
			if (end != -1) {
				String annotation = comment.substring(start, end);
				results.add(new WordLocation(comment, annotation, start));
			}
		}

		return results;
	}

	private static Pattern createAnnotationStartPattern() {

		Set<String> names = Annotation.getAnnotationNames();
		String namePatternString = StringUtils.join(names, "|");

		//@formatter:off
		return 
			Pattern.compile(
				"(?<!\\\\)" + 		// no preceding '\'
				"(" +        		// capture the match
				"\\{@(" +     		// '{@' start characters 
				namePatternString + // all known annotations with the '|' alternation 
				")\\s+?" +          // a space after the annotation name
				")"					// end capture
				);
		//@formatter:on
	}

	/*
	 * Starts at the given index and looks for the end an annotation, ignoring quoted text 
	 * and escaped characters along the way.   The value returned is the index after the last 
	 * matching annotation character.  Thus, the result can be used in substring operations that
	 * want an exclusive index.
	 */
	private static int findAnnotationEnd(String comment, int start) {

		boolean escaped = false;
		boolean inQuote = false;
		for (int i = start; i < comment.length(); i++) {

			boolean wasEscaped = escaped;
			escaped = false;
			char prev = '\0';
			if (i != 0 && !wasEscaped) {
				prev = comment.charAt(i - 1);
			}

			char c = comment.charAt(i);
			if (prev == '\\') {
				if (Annotation.ESCAPABLE_CHARS.indexOf(c) != -1) {
					escaped = true;
					continue;
				}
			}

			if (c == '"') {
				inQuote = !inQuote;
			}
			else if (c == '}') {
				if (!inQuote) {
					return i + 1;
				}
			}
		}

		return -1;
	}
}
