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
import ghidra.program.model.listing.Program;
import ghidra.util.StringUtilities;
import ghidra.util.WordLocation;
import ghidra.util.bean.field.AnnotatedTextFieldElement;
import ghidra.util.exception.AssertException;

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
	public static String fixupAnnoations(String rawCommentText, Program program) {

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
		List<Object> parts =
			doParseTextIntoTextAndAnnotations(rawCommentText, symbolFixer, program, prototype);
		for (Object part : parts) {

			if (part instanceof String) {
				String s = (String) part;
				buffy.append(s);
			}
			else if (part instanceof Annotation) {
				Annotation a = (Annotation) part;
				buffy.append(a.getAnnotationText());
			}
			else {
				throw new AssertException("Unhandled annotation piece: " + part);
			}
		}
		return buffy.toString();
	}

	private static AttributedString createPrototype() {
		Font dummyFont = new Font("monospaced", Font.PLAIN, 12);
		@SuppressWarnings("deprecation")
		FontMetrics fontMetrics = Toolkit.getDefaultToolkit().getFontMetrics(dummyFont);
		return new AttributedString("", Color.BLACK, fontMetrics);
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
		List<Object> parts =
			doParseTextIntoTextAndAnnotations(text, fixerUpper, program, prototype);
		List<FieldElement> fields = new ArrayList<>();
		for (Object part : parts) {

			if (part instanceof String) {
				String s = (String) part;
				AttributedString as = prototype.deriveAttributedString(s);
				fields.add(new TextFieldElement(as, row, column));
				column += s.length();
			}
			else if (part instanceof Annotation) {
				Annotation a = (Annotation) part;
				fields.add(new AnnotatedTextFieldElement(a, row, column));
				column += a.getAnnotationText().length();
			}
			else {
				throw new AssertException("Unhandled annotation piece: " + part);
			}
		}

		return new CompositeFieldElement(fields.toArray(new FieldElement[fields.size()]));
	}

	/**
	 * Split the given text into parts where the returned list contains either a String or 
	 * an Annotation
	 * 
	 * @param text the text to parse
	 * @param fixerUpper a function that is given a chance to convert an Annotation into a new
	 *        one
	 * @param program the program
	 * @param prototype the prototype string that contains decoration attributes
	 * @return a list that contains a mixture String or an Annotation entries
	 */
	private static List<Object> doParseTextIntoTextAndAnnotations(String text,
			Function<Annotation, Annotation> fixerUpper, Program program,
			AttributedString prototype) {

		List<Object> results = new ArrayList<>();

		List<WordLocation> annotations = getCommentAnnotations(text);
		if (annotations.isEmpty()) {
			results.add(text);
			return results;
		}

		// split the text into pieces of normal text and annotated
		int offset = 0;
		for (WordLocation word : annotations) {

			int start = word.getStart();
			if (offset != start) {
				// text between annotations
				String preceeding = text.substring(offset, start);
				results.add(preceeding);
			}

			String annotationText = word.getWord();
			Annotation annotation = new Annotation(annotationText, prototype, program);
			annotation = fixerUpper.apply(annotation);
			results.add(annotation);

			offset = start + annotationText.length();
		}

		if (offset != text.length()) { // trailing text
			results.add(text.substring(offset));
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

		boolean startQuote = false;
		int count = 0;
		for (int i = start; i < comment.length(); i++) {
			char prev = i == 0 ? '\0' : comment.charAt(i - 1);
			if (prev == '\\') {
				continue; // escaped
			}

			char c = comment.charAt(i);
			if (c == '"') {
				if (startQuote) {
					--count;
				}
				else {
					++count;
				}
				startQuote = !startQuote;
			}
			else if (c == '}') {
				if (count == 0) {
					return i + 1;
				}
			}
		}

		return -1;
	}
}
