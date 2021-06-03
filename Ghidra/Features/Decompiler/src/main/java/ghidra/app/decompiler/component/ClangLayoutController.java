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
package ghidra.app.decompiler.component;

import java.awt.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.*;

import javax.swing.JComponent;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.SearchLocation;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.listener.IndexMapper;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompile.actions.FieldBasedSearchLocation;
import ghidra.app.util.viewer.field.CommentUtils;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.Msg;

/**
 * 
 *
 * Control the GUI layout for displaying tokenized C code
 */
public class ClangLayoutController implements LayoutModel, LayoutModelListener {

	private final ClangFieldElement EMPTY_LINE_NUMBER_SPACER;

	private int maxWidth;
	private int lineNumberFieldWidth;
	private int indentWidth;
	private DecompileOptions options;
	private DecompilerPanel decompilerPanel;
	private ClangTokenGroup docroot; // Root of displayed document
	private Field[] fieldList; // Array of fields comprising layout
	private FontMetrics metrics;
	private HighlightFactory hlFactory;
	private ArrayList<LayoutModelListener> listeners;
	private Color[] syntax_color; // Foreground colors.
	private BigInteger numIndexes = BigInteger.ZERO;
	private ArrayList<ClangLine> lines = new ArrayList<>();

	private boolean showLineNumbers = true;

	private ClangFieldElement createEmptyLineNumberSpacer() {
		ClangToken lineNumberToken = ClangToken.buildSpacer(null, 0, "");
		AttributedString as = new AttributedString("", Color.WHITE, metrics);
		return new ClangFieldElement(lineNumberToken, as, 0);
	}

	public ClangLayoutController(DecompileOptions opt, DecompilerPanel decompilerPanel,
			FontMetrics met, HighlightFactory hlFactory) {
		options = opt;
		this.decompilerPanel = decompilerPanel;
		syntax_color = new Color[9];
		metrics = met;
		this.hlFactory = hlFactory;
		EMPTY_LINE_NUMBER_SPACER = createEmptyLineNumberSpacer();
		listeners = new ArrayList<>();
		buildLayouts(null, null, null, false);
	}

	public ArrayList<ClangLine> getLines() {
		return lines;
	}

	@Override
	public boolean isUniform() {
		return false;
	}

	@Override
	public Dimension getPreferredViewSize() {
		return new Dimension(maxWidth + lineNumberFieldWidth, 500);
	}

	@Override
	public BigInteger getNumIndexes() {
		return numIndexes;
	}

	@Override
	public Layout getLayout(BigInteger index) {
		if (index.compareTo(numIndexes) >= 0) {
			return null;
		}
		return new SingleRowLayout(fieldList[index.intValue()]);
	}

	@Override
	public void addLayoutModelListener(LayoutModelListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeLayoutModelListener(LayoutModelListener listener) {
		listeners.remove(listener);
	}

	@Override
	public void modelSizeChanged(IndexMapper mapper) {
		for (int i = 0; i < listeners.size(); ++i) {
			listeners.get(i).modelSizeChanged(mapper);
		}
	}

	public void modelChanged() {
		for (int i = 0; i < listeners.size(); ++i) {
			listeners.get(i).modelSizeChanged(IndexMapper.IDENTITY_MAPPER);
		}
	}

	@Override
	public void dataChanged(BigInteger start, BigInteger end) {
		for (int i = 0; i < listeners.size(); ++i) {
			listeners.get(i).dataChanged(start, end);
		}
	}

	public void layoutChanged() {
		for (int i = 0; i < listeners.size(); ++i) {
			listeners.get(i).dataChanged(BigInteger.ZERO, numIndexes);
		}
	}

	@Override
	public BigInteger getIndexAfter(BigInteger index) {
		BigInteger nextIndex = index.add(BigInteger.ONE);
		if (nextIndex.compareTo(numIndexes) >= 0) {
			return null;
		}
		return nextIndex;
	}

	@Override
	public BigInteger getIndexBefore(BigInteger index) {
		if (index.compareTo(BigInteger.ZERO) <= 0) {
			return null;
		}
		return index.subtract(BigInteger.ONE);
	}

	public int getIndexBefore(int index) {
		return index - 1;
	}

	public ClangTokenGroup getRoot() {
		return docroot;
	}

	Field[] getFields() {
		return fieldList;
	}

	private ClangTextField createTextFieldForLine(ClangLine line, int lineCount,
			boolean paintLineNumbers) {
		List<ClangToken> tokens = line.getAllTokens();

		ClangFieldElement lineNumberFieldElement =
			createLineNumberFieldElement(line, lineCount, paintLineNumbers);

		FieldElement[] elements = createFieldElementsForLine(tokens);

		int indent = line.getIndent() * indentWidth;
		int lineNumberWidth = lineNumberFieldElement.getStringWidth();
		int updatedMaxWidth = maxWidth + lineNumberWidth;
		return new ClangTextField(tokens, elements, lineNumberFieldElement, indent, updatedMaxWidth,
			hlFactory);
	}

	private FieldElement[] createFieldElementsForLine(List<ClangToken> tokens) {

		FieldElement[] elements = new FieldElement[tokens.size()];
		int columnPosition = 0;
		for (int i = 0; i < tokens.size(); ++i) {
			ClangToken token = tokens.get(i);
			Color color = syntax_color[token.getSyntaxType()];
			if (token instanceof ClangCommentToken) {
				AttributedString prototype = new AttributedString("prototype", color, metrics);
				Program program = decompilerPanel.getProgram();
				elements[i] =
					CommentUtils.parseTextForAnnotations(token.getText(), program, prototype, 0);
				columnPosition += elements[i].length();
			}
			else {
				AttributedString as = new AttributedString(token.getText(), color, metrics);
				elements[i] = new ClangFieldElement(token, as, columnPosition);
				columnPosition += as.length();
			}
		}
		return elements;
	}

	private ClangFieldElement createLineNumberFieldElement(ClangLine line, int lineCount,
			boolean paintLineNumbers) {

		if (paintLineNumbers) {
			return new LineNumberFieldElement(line.getLineNumber(), lineCount, metrics);
		}

		return EMPTY_LINE_NUMBER_SPACER;
	}

	/**
	 * Update to the current Decompiler display options
	 */
	@SuppressWarnings("deprecation")
	// ignoring the deprecated call for toolkit
	private void updateOptions() {
		syntax_color[ClangToken.KEYWORD_COLOR] = options.getKeywordColor();
		syntax_color[ClangToken.TYPE_COLOR] = options.getTypeColor();
		syntax_color[ClangToken.FUNCTION_COLOR] = options.getFunctionColor();
		syntax_color[ClangToken.COMMENT_COLOR] = options.getCommentColor();
		syntax_color[ClangToken.VARIABLE_COLOR] = options.getVariableColor();
		syntax_color[ClangToken.CONST_COLOR] = options.getConstantColor();
		syntax_color[ClangToken.PARAMETER_COLOR] = options.getParameterColor();
		syntax_color[ClangToken.GLOBAL_COLOR] = options.getGlobalColor();
		syntax_color[ClangToken.DEFAULT_COLOR] = options.getDefaultColor();

		// setting the metrics here will indirectly trigger the new font to be used deeper in 
		// the bowels of the FieldPanel (you can get the font from the metrics)
		Font font = options.getDefaultFont();
		metrics = Toolkit.getDefaultToolkit().getFontMetrics(font);
		indentWidth = metrics.stringWidth(PrettyPrinter.INDENT_STRING);
		maxWidth = indentWidth * options.getMaxWidth();
		lineNumberFieldWidth = 0;

		showLineNumbers = options.isDisplayLineNumbers();
	}

	private void buildLayoutInternal(Function function, boolean display, boolean isError) {
		updateOptions();

		// Assume docroot has been built.

		PrettyPrinter printer = new PrettyPrinter(function, docroot);
		lines = printer.getLines();

		int lineCount = lines.size();
		fieldList = new Field[lineCount]; // One field for each "C" line
		numIndexes = BigInteger.valueOf(lineCount);

		lineNumberFieldWidth = 0;
		if (showLineNumbers && !isError) {
			lineNumberFieldWidth = LineNumberFieldElement.getFieldWidth(metrics, lineCount);
		}

		for (int i = 0; i < lineCount; ++i) {
			ClangLine oneLine = lines.get(i);
			fieldList[i] = createTextFieldForLine(oneLine, lineCount, showLineNumbers);
		}

		if (display) {
			modelChanged(); // Inform the listeners that we have changed
		}
	}

	private void splitToMaxWidthLines(ArrayList<String> res, String line) {
		int maxchar;
		if ((maxWidth == 0) || (indentWidth == 0)) {
			maxchar = 40;
		}
		else {
			maxchar = maxWidth / indentWidth;
		}
		String[] toklist = line.split("[ \t]+");
		StringBuffer buf = new StringBuffer();
		int cursize = 0;
		boolean atleastone = false;
		int i = 0;
		while (i < toklist.length) {
			if (!atleastone) {
				buf.append(' ');
				buf.append(toklist[i]);
				atleastone = true;
				cursize += toklist[i].length() + 1;
				i += 1;
				continue;
			}
			if (cursize + toklist[i].length() >= maxchar) {
				String finishLine = buf.toString();
				res.add(finishLine);
				cursize = 5;
				atleastone = false;
				buf = new StringBuffer();
				buf.append("     ");
			}
			else {
				buf.append(' ');
				buf.append(toklist[i]);
				cursize += toklist[i].length() + 1;
				i += 1;
			}
		}
		String finalLine = buf.toString();
		if (finalLine.length() != 0) {
			res.add(finalLine);
		}
	}

	private boolean addErrorLayout(String errmsg) { // Add indicated error message to display
		if (docroot == null) {
			docroot = new ClangFunction(null, null);
			if (errmsg == null) {
				errmsg = "No function";
			}
		}
		if (errmsg == null) {
			return false; // No error message to add
		}
		String[] errlines_init = errmsg.split("[\n\r]+");
		ArrayList<String> errlines = new ArrayList<>();
		for (String element : errlines_init) {
			splitToMaxWidthLines(errlines, element);
		}
		for (int i = 0; i < errlines.size(); ++i) {
			ClangTokenGroup line = new ClangTokenGroup(docroot);
			ClangBreak lineBreak = new ClangBreak(line, 1);
			ClangSyntaxToken message =
				new ClangSyntaxToken(line, errlines.get(i), ClangXML.COMMENT_COLOR);
			line.AddTokenGroup(lineBreak);
			line.AddTokenGroup(message);
			docroot.AddTokenGroup(line);
		}

		return true; // true signals we have an error message
	}

	public void buildLayouts(Function function, ClangTokenGroup doc, String errmsg,
			boolean display) {
		docroot = doc;
		boolean isError = addErrorLayout(errmsg);
		buildLayoutInternal(function, display, isError);
	}

	public HighFunction getHighFunction(int i) { // Get the i'th function id in the layout
		int numfunc = docroot.numChildren();
		if ((i < 0) || (i >= numfunc)) {
			return null;
		}
		if (docroot.Child(i) instanceof ClangFunction) {
			return ((ClangFunction) docroot.Child(i)).getHighFunction();
		}
		return null;
	}

//==================================================================================================
// Search Related Methods
//==================================================================================================	

	private SearchLocation findNextTokenGoingForward(
			java.util.function.Function<String, SearchMatch> matcher, String searchString,
			FieldLocation currentLocation) {

		int row = currentLocation.getIndex().intValue();
		for (int i = row; i < fieldList.length; i++) {
			ClangTextField field = (ClangTextField) fieldList[i];
			String textLine =
				getTextLineFromOffset((i == row) ? currentLocation : null, field, true);

			SearchMatch match = matcher.apply(textLine);
			if (match != SearchMatch.NO_MATCH) {
				if (i == row) {
					String fullLine = field.getText();
					match.start += fullLine.length() - textLine.length();
				}
				FieldNumberColumnPair pair = getFieldIndexFromOffset(match.start, field);
				FieldLocation fieldLocation =
					new FieldLocation(i, pair.getFieldNumber(), 0, pair.getColumn());

				return new FieldBasedSearchLocation(fieldLocation, match.start, match.end - 1,
					searchString, true);
			}
		}
		return null;
	}

	private SearchLocation findNextTokenGoingBackward(
			java.util.function.Function<String, SearchMatch> matcher, String searchString,
			FieldLocation currentLocation) {

		int row = currentLocation.getIndex().intValue();
		for (int i = row; i >= 0; i--) {
			ClangTextField field = (ClangTextField) fieldList[i];
			String textLine =
				getTextLineFromOffset((i == row) ? currentLocation : null, field, false);

			SearchMatch match = matcher.apply(textLine);
			if (match != SearchMatch.NO_MATCH) {
				FieldNumberColumnPair pair = getFieldIndexFromOffset(match.start, field);
				FieldLocation fieldLocation =
					new FieldLocation(i, pair.getFieldNumber(), 0, pair.getColumn());

				return new FieldBasedSearchLocation(fieldLocation, match.start, match.end - 1,
					searchString, false);
			}
		}
		return null;
	}

	public SearchLocation findNextTokenForSearchRegex(String searchString,
			FieldLocation currentLocation, boolean forwardSearch) {

		Pattern pattern = null;
		try {
			pattern = Pattern.compile(searchString, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
		}
		catch (PatternSyntaxException e) {
			Msg.showError(this, decompilerPanel, "Regular Expression Syntax Error", e.getMessage());
			return null;
		}

		Pattern finalPattern = pattern;
		if (forwardSearch) {

			java.util.function.Function<String, SearchMatch> function = textLine -> {

				Matcher matcher = finalPattern.matcher(textLine);
				if (matcher.find()) {
					int start = matcher.start();
					int end = matcher.end();
					return new SearchMatch(start, end);
				}

				return SearchMatch.NO_MATCH;
			};

			return findNextTokenGoingForward(function, searchString, currentLocation);
		}

		java.util.function.Function<String, SearchMatch> reverse = textLine -> {

			Matcher matcher = finalPattern.matcher(textLine);

			if (!matcher.find()) {
				return SearchMatch.NO_MATCH;
			}

			int start = matcher.start();
			int end = matcher.end();

			// Since the matcher can only match from the start to end of line, we need
			// to find all matches and then take the last match
			while (matcher.find()) {
				start = matcher.start();
				end = matcher.end();
			}

			return new SearchMatch(start, end);
		};

		return findNextTokenGoingBackward(reverse, searchString, currentLocation);
	}

	public SearchLocation findNextTokenForSearch(String searchString, FieldLocation currentLocation,
			boolean forwardSearch) {

		if (forwardSearch) {

			java.util.function.Function<String, SearchMatch> function = textLine -> {

				int index = StringUtils.indexOfIgnoreCase(textLine, searchString);
				if (index == -1) {
					return SearchMatch.NO_MATCH;
				}
				return new SearchMatch(index, index + searchString.length());
			};

			return findNextTokenGoingForward(function, searchString, currentLocation);
		}

		java.util.function.Function<String, SearchMatch> function = textLine -> {

			int index = StringUtils.lastIndexOfIgnoreCase(textLine, searchString);
			if (index == -1) {
				return SearchMatch.NO_MATCH;
			}
			return new SearchMatch(index, index + searchString.length());
		};

		return findNextTokenGoingBackward(function, searchString, currentLocation);
	}

	private String getTextLineFromOffset(FieldLocation location, ClangTextField textField,
			boolean forwardSearch) {
		if (location == null) { // the cursor location is not on this line; use all of the text
			return textField.getText();
		}

		if (textField.getText().isEmpty()) { // the cursor is on blank line
			return "";
		}

		String partialText = textField.getText();

		if (forwardSearch) {

			// Protects against the location column being out of range (this can
			// happen if we're searching forward and the cursor is past the last token).
			if (location.getCol() + 1 >= partialText.length()) {
				return "";
			}
			return partialText.substring(location.getCol() + 1);
		}

		// backwards search
		return partialText.substring(0, location.getCol());
	}

	private FieldNumberColumnPair getFieldIndexFromOffset(int screenOffset,
			ClangTextField textField) {
		RowColLocation rowColLocation = textField.textOffsetToScreenLocation(screenOffset);

		// we use 0 here because currently there is only one field, which is the entire line
		return new FieldNumberColumnPair(0, rowColLocation.col());
	}

	private static class SearchMatch {
		private static SearchMatch NO_MATCH = new SearchMatch(-1, -1);
		private int start;
		private int end;

		SearchMatch(int start, int end) {
			this.start = start;
			this.end = end;
		}
	}
//==================================================================================================
// End Search Related Methods
//==================================================================================================	

	ClangToken getTokenForLocation(FieldLocation fieldLocation) {
		int row = fieldLocation.getIndex().intValue();
		ClangTextField field = (ClangTextField) fieldList[row];
		return field.getToken(fieldLocation);
	}

	public void locationChanged(FieldLocation loc, Field field, Color locationColor,
			Color parenColor) {
		// Highlighting is now handled through the decompiler panel's highlight controller.
	}

	public boolean changePending() {
		return false;
	}

	@Override
	public void flushChanges() {
		// nothing to do
	}
//==================================================================================================
// Inner Classes
//==================================================================================================	

	private static class LineNumberFieldElement extends ClangFieldElement {
		private static final Color FOREGROUND_COLOR = new Color(125, 125, 125);
		private int uniformWidth;

		private LineNumberFieldElement(int lineNumber, int lineCount, FontMetrics fontMetrics) {
			super(ClangToken.buildSpacer(null, 0, ""), createAttributedLineNumberString(lineNumber,
				lineCount, FOREGROUND_COLOR, fontMetrics), 0);
			uniformWidth = calculateUniformStringWidth(fontMetrics);
		}

		private static String createLineNumberString(int lineNumber, int lineCount) {

			String lineCountString = Integer.toString(lineCount);
			int maxNumberOfDigits = lineCountString.length();

			String lineNumberString = Integer.toString(lineNumber);
			int lineNumberLength = lineNumberString.length();
			int padLength = maxNumberOfDigits - lineNumberLength;

			StringBuffer buffy = new StringBuffer();
			for (int i = 0; i < padLength; i++) {
				buffy.append(' ');
			}
			buffy.append(lineNumberString).append(' '); // space for separation
			return buffy.toString();
		}

		private static AttributedString createAttributedLineNumberString(int lineNumber,
				int lineCount, Color foregroundColor, FontMetrics fontMetrics) {
			return new AttributedString(createLineNumberString(lineNumber, lineCount),
				foregroundColor, fontMetrics);
		}

		static int getFieldWidth(FontMetrics fontMetrics, int lineCnt) {
			int largestCharacterWidth = getLargestCharacterWidth(fontMetrics);
			int numberOfCharacters = createLineNumberString(0, lineCnt).length();
			return numberOfCharacters * largestCharacterWidth;
		}

		private int calculateUniformStringWidth(FontMetrics fontMetrics) {
			int largestCharacterWidth = getLargestCharacterWidth(fontMetrics);
			int numberOfCharacters = getText().length();
			return numberOfCharacters * largestCharacterWidth;
		}

		private static int getLargestCharacterWidth(FontMetrics fontMetrics) {
			// use the biggest number char (since that's what we paint in this object)
			// for determining the a space to use as a guide
			return fontMetrics.stringWidth("9");
		}

		@Override
		public void paint(JComponent c, Graphics g, int x, int y) {
			// paint our text
			super.paint(c, g, 0, 0);

			// paint a vertical rule
			Color color = getColor(0);
			g.setColor(color);

			FontMetrics fontMetrics = g.getFontMetrics();
			int topX = fontMetrics.getMaxAscent() + 1; // fudge for font painting differences
			int maxDescent = fontMetrics.getMaxDescent();

			int baselineX = maxDescent + 1; // fudge for font painting differences
			g.drawLine(uniformWidth, -topX, uniformWidth, baselineX);
		}

		@Override
		// overridden so that our width reflects our custom width
		public int getStringWidth() {
			return uniformWidth + 3; // fudge for keeping the c code off the line number bar
		}
	}

	private class FieldNumberColumnPair {
		private final int fieldNumber;
		private final int column;

		FieldNumberColumnPair(int fieldNumber, int column) {
			this.fieldNumber = fieldNumber;
			this.column = column;

		}

		int getFieldNumber() {
			return fieldNumber;
		}

		int getColumn() {
			return column;
		}
	}

}
