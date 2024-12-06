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

import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.listener.IndexMapper;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.decompiler.*;
import ghidra.app.util.SymbolInspector;
import ghidra.app.util.viewer.field.CommentUtils;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.UndefinedFunction;

/**
 * Control the GUI layout for displaying tokenized C code
 */
public class ClangLayoutController implements LayoutModel, LayoutModelListener {

	private int maxWidth;
	private int indentWidth;
	private SymbolInspector symbolInspector;
	private DecompilerPanel decompilerPanel;
	private DecompileOptions options;
	private ClangTokenGroup docroot; // Root of displayed document
	private Field[] fieldList; // Array of fields comprising layout
	private FontMetrics metrics;
	private FieldHighlightFactory hlFactory;
	private List<LayoutModelListener> listeners;
	private Color[] syntaxColor; // Foreground colors.
	private BigInteger numIndexes = BigInteger.ZERO;
	private List<ClangLine> lines = new ArrayList<>();

	private boolean showLineNumbers = true;

	public ClangLayoutController(DecompileOptions opt, DecompilerPanel decompilerPanel,
			FontMetrics met, FieldHighlightFactory hlFactory) {
		options = opt;
		this.decompilerPanel = decompilerPanel;
		syntaxColor = new Color[ClangToken.MAX_COLOR];
		metrics = met;
		this.hlFactory = hlFactory;
		listeners = new ArrayList<>();
		buildLayouts(null, null, null, false);

		DecompilerController controller = decompilerPanel.getController();
		ServiceProvider serviceProvider = controller.getServiceProvider();
		symbolInspector = new SymbolInspector(serviceProvider, decompilerPanel);
	}

	public List<ClangLine> getLines() {
		return lines;
	}

	@Override
	public boolean isUniform() {
		return false;
	}

	@Override
	public Dimension getPreferredViewSize() {
		return new Dimension(maxWidth, 500);
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
		for (LayoutModelListener listener : listeners) {
			listener.modelSizeChanged(mapper);
		}
	}

	public void modelChanged() {
		for (LayoutModelListener listener : listeners) {
			listener.modelSizeChanged(IndexMapper.IDENTITY_MAPPER);
		}
	}

	@Override
	public void dataChanged(BigInteger start, BigInteger end) {
		for (LayoutModelListener listener : listeners) {
			listener.dataChanged(start, end);
		}
	}

	public void layoutChanged() {
		for (LayoutModelListener listener : listeners) {
			listener.dataChanged(BigInteger.ZERO, numIndexes);
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

		FieldElement[] elements = createFieldElementsForLine(tokens);

		int indent = line.getIndent() * indentWidth;
		int updatedMaxWidth = maxWidth;
		return new ClangTextField(tokens, elements, indent, line.getLineNumber(), updatedMaxWidth,
			hlFactory);
	}

	private FieldElement[] createFieldElementsForLine(List<ClangToken> tokens) {

		FieldElement[] elements = new FieldElement[tokens.size()];
		int columnPosition = 0;
		for (int i = 0; i < tokens.size(); ++i) {
			ClangToken token = tokens.get(i);
			Color color = getTokenColor(token);

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

	private Color getTokenColor(ClangToken token) {

		Color tokenColor = syntaxColor[token.getSyntaxType()];
		if (token instanceof ClangFuncNameToken clangFunctionToken) {
			Program program = decompilerPanel.getProgram();
			Function function = DecompilerUtils.getFunction(program, clangFunctionToken);
			if (function == null || function instanceof UndefinedFunction) {
				return null;
			}
			Symbol symbol = function.getSymbol();
			return symbolInspector.getColor(symbol);
		}
		return tokenColor;
	}

	/**
	 * Update to the current Decompiler display options
	 */
	@SuppressWarnings("deprecation")
	// ignoring the deprecated call for toolkit
	private void updateOptions() {
		syntaxColor[ClangToken.KEYWORD_COLOR] = options.getKeywordColor();
		syntaxColor[ClangToken.TYPE_COLOR] = options.getTypeColor();
		syntaxColor[ClangToken.COMMENT_COLOR] = options.getCommentColor();
		syntaxColor[ClangToken.FUNCTION_COLOR] = null; // not used by the UI
		syntaxColor[ClangToken.VARIABLE_COLOR] = options.getVariableColor();
		syntaxColor[ClangToken.CONST_COLOR] = options.getConstantColor();
		syntaxColor[ClangToken.PARAMETER_COLOR] = options.getParameterColor();
		syntaxColor[ClangToken.GLOBAL_COLOR] = options.getGlobalColor();
		syntaxColor[ClangToken.DEFAULT_COLOR] = options.getDefaultColor();
		syntaxColor[ClangToken.ERROR_COLOR] = options.getErrorColor();
		syntaxColor[ClangToken.SPECIAL_COLOR] = options.getSpecialColor();

		// setting the metrics here will indirectly trigger the new font to be used deeper in
		// the bowels of the FieldPanel (you can get the font from the metrics)
		Font font = options.getDefaultFont();
		metrics = Toolkit.getDefaultToolkit().getFontMetrics(font);
		indentWidth = metrics.stringWidth(PrettyPrinter.INDENT_STRING);
		maxWidth = indentWidth * options.getMaxWidth();

		showLineNumbers = options.isDisplayLineNumbers();
	}

	private void buildLayoutInternal(Function function, boolean display, boolean isError) {
		updateOptions();

		// Assume docroot has been built.

		PrettyPrinter printer = new PrettyPrinter(function, docroot, null);
		lines = printer.getLines();

		int lineCount = lines.size();
		fieldList = new Field[lineCount]; // One field for each "C" line
		numIndexes = BigInteger.valueOf(lineCount);

		for (int i = 0; i < lineCount; ++i) {
			ClangLine oneLine = lines.get(i);
			fieldList[i] = createTextFieldForLine(oneLine, lineCount, showLineNumbers);
		}

		if (display) {
			modelChanged(); // Inform the listeners that we have changed
		}
	}

	private void splitToMaxWidthLines(List<String> res, String line) {
		int maxchar;
		if ((maxWidth == 0) || (indentWidth == 0)) {
			maxchar = 40;
		}
		else {
			maxchar = maxWidth / indentWidth;
		}
		String[] toklist = line.split("[ \t]+");
		StringBuilder buf = new StringBuilder();
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
				buf = new StringBuilder();
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
		List<String> errlines = new ArrayList<>();
		for (String element : errlines_init) {
			splitToMaxWidthLines(errlines, element);
		}
		for (String errline : errlines) {
			ClangTokenGroup line = new ClangTokenGroup(docroot);
			ClangBreak lineBreak = new ClangBreak(line, 1);
			ClangSyntaxToken message =
				new ClangSyntaxToken(line, errline, ClangToken.COMMENT_COLOR);
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

	public void locationChanged(FieldLocation loc, Field field, Color locationColor,
			Color parenColor) {
		// Highlighting is now handled through the decompiler panel's highlight controller.
	}

	@Override
	public void flushChanges() {
		// nothing to do
	}
}
