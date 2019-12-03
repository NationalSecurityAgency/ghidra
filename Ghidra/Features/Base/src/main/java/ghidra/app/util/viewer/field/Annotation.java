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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import docking.widgets.fieldpanel.field.AttributedString;
import ghidra.app.nav.Navigatable;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;

public class Annotation {
	/**
	 * A pattern to match text between two quote characters and to capture that text.  This 
	 * pattern does not match quote characters that are escaped with a '\' character.
	 */
	private static final Pattern QUOTATION_PATTERN =
		Pattern.compile("(?<!\\\\)[\"](.*?)(?<!\\\\)[\"]");

	private static Map<String, AnnotatedStringHandler> ANNOTATED_STRING_MAP;

	private String annotationText;
	private String[] annotationParts;
	private AnnotatedStringHandler annotatedStringHandler;
	private AttributedString displayString;

	private static Map<String, AnnotatedStringHandler> getAnnotatedStringHandlerMap() {
		if (ANNOTATED_STRING_MAP == null) { // lazy init due to our use of ClassSearcher
			ANNOTATED_STRING_MAP = createAnnotatedStringHandlerMap();
		}
		return ANNOTATED_STRING_MAP;
	}

	// locates AnnotatedStringHandler implementations to handle annotations 
	private static Map<String, AnnotatedStringHandler> createAnnotatedStringHandlerMap() {
		Map<String, AnnotatedStringHandler> map = new HashMap<>();

		// find all instances of AnnotatedString
		List<AnnotatedStringHandler> instances =
			ClassSearcher.getInstances(AnnotatedStringHandler.class);

		for (AnnotatedStringHandler instance : instances) {
			String[] supportedAnnotations = instance.getSupportedAnnotations();
			for (String supportedAnnotation : supportedAnnotations) {
				map.put(supportedAnnotation, instance);
			}
		}

		return Collections.unmodifiableMap(map);
	}

	/**
	 * Constructor
	 * <b>Note</b>: This constructor assumes that the string starts with "{<pre>@</pre>" and ends with '}'
	 * 
	 * @param annotationText The complete annotation text.
	 * @param prototypeString An AttributedString that provides the attributes for the display 
	 * text this Annotation can create
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

	private String[] parseAnnotationText(String theAnnotationText) {
		StringBuffer buffer = new StringBuffer(theAnnotationText);

		// strip off the brackets
		buffer.delete(0, 2); // remove '{' and '@'
		buffer.deleteCharAt(buffer.length() - 1);

		// first split out the tokens on '"' so that annotations can have groupings with 
		// whitespace
		int unqouotedOffset = 0;
		List<String> tokens = new ArrayList<>();
		Matcher matcher = QUOTATION_PATTERN.matcher(buffer.toString());
		while (matcher.find()) {
			// put all text in the buffer, 
			int quoteStart = matcher.start();
			String contentBeforeQuote = buffer.substring(unqouotedOffset, quoteStart);
			grabTokens(tokens, contentBeforeQuote);
			unqouotedOffset = matcher.end();

			String quotedContent = matcher.group(1); // group 0 is the entire string
			tokens.add(quotedContent);
		}

		// handle any remaining part of the text after quoted sections
		if (unqouotedOffset < buffer.length()) {
			String remainingString = buffer.substring(unqouotedOffset);
			grabTokens(tokens, remainingString);
		}

		// split on whitespace
		return tokens.toArray(new String[tokens.size()]);
	}

	private void grabTokens(List<String> tokenContainer, String content) {
		String[] strings = content.split("\\s");
		for (String string : strings) {
			// 0 length strings can happen when 'content' begins with a space
			if (string.length() > 0) {
				tokenContainer.add(string);
			}
		}
	}

	public String getAnnotationText() {
		return annotationText;
	}

	public static AnnotatedStringHandler[] getAnnotatedStringHandlers() {
		Set<AnnotatedStringHandler> annotations =
			new HashSet<>(getAnnotatedStringHandlerMap().values());
		AnnotatedStringHandler[] retVal = new AnnotatedStringHandler[annotations.size()];
		annotations.toArray(retVal);
		return retVal;
	}

	/*package*/ static Set<String> getAnnotationNames() {
		return Collections.unmodifiableSet(getAnnotatedStringHandlerMap().keySet());
	}

}
