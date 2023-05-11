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
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.*;
import java.util.List;
import java.util.function.Supplier;

import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.DockingUtils;
import docking.util.AnimationUtils;
import docking.util.SwingAnimationCallback;
import docking.widgets.EventTrigger;
import docking.widgets.SearchLocation;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.field.FieldElement;
import docking.widgets.fieldpanel.listener.*;
import docking.widgets.fieldpanel.support.*;
import docking.widgets.indexedscrollpane.IndexedScrollPane;
import generic.theme.GColor;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.hover.DecompilerHoverService;
import ghidra.app.decompiler.component.margin.*;
import ghidra.app.plugin.core.decompile.DecompilerClipboardProvider;
import ghidra.app.plugin.core.decompile.actions.FieldBasedSearchLocation;
import ghidra.app.util.viewer.util.ScrollpaneAlignedHorizontalLayout;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.*;
import ghidra.util.bean.field.AnnotatedTextFieldElement;
import ghidra.util.task.SwingUpdateManager;

/**
 * Class to handle the display of a decompiled function
 */
public class DecompilerPanel extends JPanel implements FieldMouseListener, FieldLocationListener,
		FieldSelectionListener, ClangHighlightListener, LayoutListener {

	private final static Color NON_FUNCTION_BACKGROUND_COLOR_DEF = new GColor("color.bg.undefined");

	// Default color for specially highlighted tokens
	private final static Color SPECIAL_COLOR_DEF =
		new GColor("color.bg.decompiler.highlights.special");

	private final DecompilerController controller;
	private final DecompileOptions options;
	private LineNumberDecompilerMarginProvider lineNumbersMargin;

	private final DecompilerFieldPanel fieldPanel;
	private ClangLayoutController layoutController;
	private final IndexedScrollPane scroller;
	private final JComponent taskMonitorComponent;

	private final List<DecompilerMarginProvider> marginProviders = new ArrayList<>();
	private final VerticalLayoutPixelIndexMap pixmap = new VerticalLayoutPixelIndexMap();

	private FieldHighlightFactory hlFactory;
	private ClangHighlightController highlightController;
	private Map<String, ClangDecompilerHighlighter> highlightersById = new HashMap<>();
	private PendingHighlightUpdate pendingHighlightUpdate;
	private SwingUpdateManager highlighCursorUpdater = new SwingUpdateManager(() -> {
		if (pendingHighlightUpdate != null) {
			pendingHighlightUpdate.doUpdate();
			pendingHighlightUpdate = null;
		}
	});

	private int middleMouseHighlightButton;
	private Color middleMouseHighlightColor;
	private Color currentVariableHighlightColor;
	private Color searchHighlightColor;
	private SearchLocation currentSearchLocation;

	private DecompileData decompileData = new EmptyDecompileData("No Function");
	private final DecompilerClipboardProvider clipboard;

	private Color originalBackgroundColor;
	private boolean useNonFunctionColor = false;
	private boolean navitationEnabled = true;

	private DecompilerHoverProvider decompilerHoverProvider;

	DecompilerPanel(DecompilerController controller, DecompileOptions options,
			DecompilerClipboardProvider clipboard, JComponent taskMonitorComponent) {
		this.controller = controller;
		this.options = options;
		this.clipboard = clipboard;
		this.taskMonitorComponent = taskMonitorComponent;
		FontMetrics metrics = getFontMetrics(options);
		if (clipboard != null) {
			clipboard.setFontMetrics(metrics);
		}
		hlFactory = new SearchHighlightFactory();

		layoutController = new ClangLayoutController(options, this, metrics, hlFactory);
		fieldPanel = new DecompilerFieldPanel(layoutController);
		setBackground(options.getBackgroundColor());

		scroller = new IndexedScrollPane(fieldPanel);
		fieldPanel.addFieldSelectionListener(this);
		fieldPanel.addFieldMouseListener(this);
		fieldPanel.addFieldLocationListener(this);
		fieldPanel.addLayoutListener(this);

		decompilerHoverProvider = new DecompilerHoverProvider();

		searchHighlightColor = options.getSearchHighlightColor();
		currentVariableHighlightColor = options.getCurrentVariableHighlightColor();
		middleMouseHighlightColor = options.getMiddleMouseHighlightColor();
		middleMouseHighlightButton = options.getMiddleMouseHighlightButton();

		setLayout(new BorderLayout());
		add(scroller);
		add(taskMonitorComponent, BorderLayout.SOUTH);

		setPreferredSize(new Dimension(600, 400));
		setDecompileData(new EmptyDecompileData("No Function"));

		if (options.isDisplayLineNumbers()) {
			addMarginProvider(lineNumbersMargin = new LineNumberDecompilerMarginProvider());
		}
	}

	public List<ClangLine> getLines() {
		return layoutController.getLines();
	}

	public List<Field> getFields() {
		return Arrays.asList(layoutController.getFields());
	}

	public FieldPanel getFieldPanel() {
		return fieldPanel;
	}

//==================================================================================================
// Highlight Methods
//==================================================================================================

	public TokenHighlightColors getSecondaryHighlightColors() {
		return highlightController.getSecondaryHighlightColors();
	}

	public boolean hasSecondaryHighlights(Function function) {
		return highlightController.hasSecondaryHighlights(function);
	}

	public boolean hasSecondaryHighlight(ClangToken token) {
		return highlightController.hasSecondaryHighlight(token);
	}

	public Color getSecondaryHighlight(ClangToken token) {
		return highlightController.getSecondaryHighlight(token);
	}

	public TokenHighlights getHighlights(DecompilerHighlighter highligter) {
		return highlightController.getHighlighterHighlights(highligter);
	}

	private Set<ClangDecompilerHighlighter> getSecondaryHighlihgtersByFunction(Function function) {
		return highlightController.getSecondaryHighlighters(function);
	}

	/**
	 * Removes all secondary highlights for the current function
	 * 
	 * @param function the function containing the secondary highlights
	 */
	public void removeSecondaryHighlights(Function function) {
		highlightController.removeSecondaryHighlights(function);
	}

	public void removeSecondaryHighlight(ClangToken token) {
		highlightController.removeSecondaryHighlights(token);
	}

	public void addSecondaryHighlight(ClangToken token) {
		ColorProvider cp = highlightController.getRandomColorProvider();
		addSecondaryHighlight(token.getText(), cp);
	}

	public void addSecondaryHighlight(ClangToken token, Color color) {
		ColorProvider cp = t -> color;
		addSecondaryHighlight(token.getText(), cp);
	}

	private void addSecondaryHighlight(String tokenText, ColorProvider colorProvider) {
		NameTokenMatcher matcher = new NameTokenMatcher(tokenText, colorProvider);
		ClangDecompilerHighlighter highlighter = createHighlighter(matcher);
		applySecondaryHighlights(highlighter);
	}

	private void applySecondaryHighlights(ClangDecompilerHighlighter highlighter) {
		Function function = decompileData.getFunction();
		highlightController.addSecondaryHighlighter(function, highlighter);
		highlighter.applyHighlights();
	}

	private void togglePrimaryHighlight(FieldLocation location, Field field, Color highlightColor) {
		ClangToken token = ((ClangTextField) field).getToken(location);
		Supplier<List<ClangToken>> lazyTokens = () -> findTokensByName(token.getText());
		highlightController.togglePrimaryHighlights(middleMouseHighlightColor, lazyTokens);
	}

	void addHighlighterHighlights(ClangDecompilerHighlighter highlighter,
			Supplier<? extends Collection<ClangToken>> tokens, ColorProvider colorProvider) {
		highlightController.addHighlighterHighlights(highlighter, tokens, colorProvider);
	}

	void removeHighlighterHighlights(DecompilerHighlighter highlighter) {
		highlightController.removeHighlighterHighlights(highlighter);
	}

	public ClangDecompilerHighlighter createHighlighter(CTokenHighlightMatcher tm) {
		UUID uuId = UUID.randomUUID();
		String id = uuId.toString();
		return createHighlighter(id, tm);
	}

	public ClangDecompilerHighlighter createHighlighter(String id, CTokenHighlightMatcher tm) {
		ClangDecompilerHighlighter currentHighlighter = highlightersById.get(id);
		if (currentHighlighter != null) {
			currentHighlighter.dispose();
		}

		ClangDecompilerHighlighter newHighlighter = new ClangDecompilerHighlighter(id, this, tm);
		highlightersById.put(id, newHighlighter);
		highlightController.addHighlighter(newHighlighter);
		return newHighlighter;
	}

	public DecompilerHighlighter getHighlighter(String id) {
		return highlightersById.get(id);
	}

	void removeHighlighter(String id) {
		ClangDecompilerHighlighter highlighter = highlightersById.remove(id);
		highlightController.removeHighlighter(highlighter);
	}

	public void clearPrimaryHighlights() {
		highlightController.clearPrimaryHighlights();
	}

	public void addHighlights(Set<Varnode> varnodes, ColorProvider colorProvider) {
		ClangTokenGroup root = layoutController.getRoot();
		highlightController.addPrimaryHighlights(root, colorProvider);
	}

	public void addHighlights(Set<PcodeOp> ops, Color hlColor) {
		ClangTokenGroup root = layoutController.getRoot();
		highlightController.addPrimaryHighlights(root, ops, hlColor);
	}

	public void setHighlightController(ClangHighlightController highlightController) {
		if (this.highlightController != null) {
			this.highlightController.removeListener(this);
		}

		this.highlightController = ClangHighlightController.dummyIfNull(highlightController);
		highlightController.setHighlightColor(currentVariableHighlightColor);
		highlightController.addListener(this);
	}

	public ClangHighlightController getHighlightController() {
		return highlightController;
	}

	@Override
	public void tokenHighlightsChanged() {
		repaint();
	}

	/**
	 * This function is used to alert the panel that a token was renamed. If the token being renamed
	 * had a secondary highlight, we must re-apply the highlight to the new token.
	 * 
	 * <p>
	 * This is not needed for highlighter service highlights, since they get called again to
	 * re-apply highlights. It is up to that highlighter to determine if highlighting still applies
	 * to the new token name. Alternatively, for secondary highlights, we know the user chose the
	 * highlight based upon name. Thus, when the name changes, we need to take action to update the
	 * secondary highlight.
	 * 
	 * @param token the token being renamed
	 * @param newName the new name of the token
	 */
	public void tokenRenamed(ClangToken token, String newName) {

		Color hlColor = highlightController.getSecondaryHighlight(token);
		if (hlColor == null) {
			return; // not highlighted
		}

		// remove the old highlighter
		highlightController.removeSecondaryHighlights(token);

		controller.doWhenNotBusy(() -> {
			addSecondaryHighlight(newName, t -> hlColor);
		});
	}

	private void cloneGlobalHighlighters(DecompilerPanel sourcePanel) {

		Set<ClangDecompilerHighlighter> globalHighlighters =
			sourcePanel.highlightController.getGlobalHighlighters();
		for (ClangDecompilerHighlighter otherHighlighter : globalHighlighters) {

			ClangDecompilerHighlighter newHighlighter = otherHighlighter.clone(this);
			highlightersById.put(newHighlighter.getId(), newHighlighter);

			TokenHighlights otherHighlighterTokens =
				sourcePanel.highlightController.getHighlighterHighlights(otherHighlighter);
			if (otherHighlighterTokens == null || otherHighlighterTokens.isEmpty()) {
				// The highlighter has been created but no highlights have been applied.  It is up
				// to the client to apply the highlights. The new highlighter will respond to the
				// client request if the later apply the highlights.
				continue;
			}

			newHighlighter.applyHighlights();
		}
	}

	/**
	 * Called by the provider to clone all highlights in the source panel and apply them to this
	 * panel
	 * 
	 * @param sourcePanel the panel that was cloned
	 */
	public void cloneHighlights(DecompilerPanel sourcePanel) {

		cloneGlobalHighlighters(sourcePanel);

		//
		// Keep only those secondary highlighters for the current function.  This ensures that the
		// clone will match the cloned decompiler.
		//
		Function function = decompileData.getFunction();
		Set<ClangDecompilerHighlighter> secondaryHighlighters =
			sourcePanel.getSecondaryHighlihgtersByFunction(function);

		//
		// We do NOT clone the secondary highlighters.  This allows the user the remove them
		// from the primary provider without effecting the cloned provider and vice versa.
		//
		for (ClangDecompilerHighlighter highlighter : secondaryHighlighters) {
			ClangDecompilerHighlighter newHighlighter = highlighter.copy(this);
			highlightersById.put(newHighlighter.getId(), newHighlighter);
			applySecondaryHighlights(newHighlighter);
		}
	}

//==================================================================================================
// End Highlight Methods
//==================================================================================================

	@Override
	public void setBackground(Color bg) {
		originalBackgroundColor = bg;
		if (useNonFunctionColor) {
			bg = NON_FUNCTION_BACKGROUND_COLOR_DEF;
		}
		if (fieldPanel != null) {
			fieldPanel.setBackgroundColor(bg);
		}
		super.setBackground(bg);
	}

	/**
	 * This function sets the current window display based on our display state
	 * 
	 * @param decompileData the new data
	 */
	void setDecompileData(DecompileData decompileData) {
		if (layoutController == null) {
			// we've been disposed!
			return;
		}

		DecompileData oldData = this.decompileData;
		this.decompileData = decompileData;
		Function function = decompileData.getFunction();
		if (decompileData.hasDecompileResults()) {
			layoutController.buildLayouts(function, decompileData.getCCodeMarkup(), null, true);
			if (decompileData.getDebugFile() != null) {
				controller.setStatusMessage(
					"Debug file generated: " + decompileData.getDebugFile().getAbsolutePath());
			}
		}
		else {
			layoutController.buildLayouts(null, null, decompileData.getErrorMessage(), true);
		}

		setLocation(oldData, decompileData);

		decompilerHoverProvider.setProgram(decompileData.getProgram());

		// give user notice when seeing the decompile of a non-function
		useNonFunctionColor = function instanceof UndefinedFunction;
		setBackground(originalBackgroundColor);

		if (clipboard != null) {
			clipboard.selectionChanged(null);
		}

		// don't highlight search results across functions
		currentSearchLocation = null;

		reapplySecondaryHighlights();
		reapplyGlobalHighlights();
	}

	private void reapplyGlobalHighlights() {

		Function function = decompileData.getFunction();
		if (function == null) {
			return;
		}

		Set<ClangDecompilerHighlighter> globalHighlighters =
			highlightController.getGlobalHighlighters();
		for (ClangDecompilerHighlighter highlighter : globalHighlighters) {
			highlighter.clearHighlights();
			highlighter.applyHighlights();
		}
	}

	private void reapplySecondaryHighlights() {

		Function function = decompileData.getFunction();
		if (function == null) {
			return;
		}

		Set<ClangDecompilerHighlighter> secondaryHighlighters =
			getSecondaryHighlihgtersByFunction(function);
		for (ClangDecompilerHighlighter highlighter : secondaryHighlighters) {
			highlighter.clearHighlights();
			highlighter.applyHighlights();
		}
	}

	private void setLocation(DecompileData oldData, DecompileData newData) {
		Function function = oldData.getFunction();
		if (SystemUtilities.isEqual(function, newData.getFunction())) {
			return;
		}

		ProgramLocation location = newData.getLocation();
		if (location != null) {
			setLocation(location, newData.getViewerPosition());
		}
	}

	public ClangLayoutController getLayoutController() {
		return layoutController;
	}

	public boolean containsLocation(ProgramLocation location) {
		return decompileData.contains(location);
	}

	public void setLocation(ProgramLocation location, ViewerPosition viewerPosition) {
		repaint();
		if (location.getAddress() == null) {
			return;
		}

		if (viewerPosition != null) {
			fieldPanel.setViewerPosition(viewerPosition.getIndex(), viewerPosition.getXOffset(),
				viewerPosition.getYOffset());
		}

		if (location instanceof DecompilerLocation) {
			DecompilerLocation decompilerLocation = (DecompilerLocation) location;
			fieldPanel.goTo(BigInteger.valueOf(decompilerLocation.getLineNumber()), 0, 0,
				decompilerLocation.getCharPos(), false);
			return;
		}

		//
		// Try to figure out where the given location's address maps to.  If we can find the
		// line that contains the address, the go to the beginning of that line.  (We do not try
		// to go to an actual token, since multiple tokens can share an address, we woudln't know
		// which token is best.)
		//
		// Note:  at the time of this writing, not all fields have an address value.  For
		//        example, the ClangFuncNameToken, does not have an address.  (It seems that most
		//        of the tokens in the function signature do not have an address, which can
		//        probably be fixed.)   So, to deal with this oddity, we will have some special
		//        case code below.
		//
		Address address = location.getAddress();
		if (goToFunctionSignature(address)) {
			// special case: the address is at the function entry, which means we just navigate
			// to the signature
			return;
		}

		List<ClangToken> tokens =
			DecompilerUtils.getTokensFromView(layoutController.getFields(), address);
		goToBeginningOfLine(tokens);
	}

	private boolean goToFunctionSignature(Address address) {

		if (!decompileData.hasDecompileResults()) {
			return false;
		}

		Address entry = decompileData.getFunction().getEntryPoint();
		if (!entry.equals(address)) {
			return false;
		}

		List<ClangLine> lines = layoutController.getLines();
		ClangLine signatureLine = getFunctionSignatureLine(lines);
		if (signatureLine == null) {
			return false; // can happen when there is no function decompiled
		}

		// -1 since the FieldPanel is 0-based; we are 1-based
		int lineNumber = signatureLine.getLineNumber() - 1;
		fieldPanel.goTo(BigInteger.valueOf(lineNumber), 0, 0, 0, false);

		return true;
	}

	private ClangLine getFunctionSignatureLine(List<ClangLine> functionLines) {
		for (ClangLine line : functionLines) {
			List<ClangToken> tokens = line.getAllTokens();
			for (ClangToken token : tokens) {
				if (token.Parent() instanceof ClangFuncProto) {
					return line;
				}
			}
		}
		return null;
	}

	/**
	 * Put cursor on first token in the list
	 * 
	 * @param tokens the tokens to search for
	 */
	private void goToBeginningOfLine(List<ClangToken> tokens) {
		if (tokens.isEmpty()) {
			return;
		}

		int firstLineNumber =
			DecompilerUtils.findIndexOfFirstField(tokens, layoutController.getFields());
		if (firstLineNumber != -1) {
			fieldPanel.goTo(BigInteger.valueOf(firstLineNumber), 0, 0, 0, false);
		}
	}

	public void goToToken(ClangToken token) {

		ClangLine line = token.getLineParent();

		int offset = 0;
		List<ClangToken> tokens = line.getAllTokens();
		for (ClangToken lineToken : tokens) {
			if (lineToken.equals(token)) {
				break;
			}
			offset += lineToken.getText().length();
		}

		// -1 since the FieldPanel is 0-based; we are 1-based
		int lineNumber = line.getLineNumber() - 1;
		int column = offset;
		FieldLocation start = getCursorPosition();

		int distance = getOffscreenDistance(lineNumber);
		if (distance == 0) {
			fieldPanel.navigateTo(lineNumber, column);
			return;
		}

		ScrollingCallback callback = new ScrollingCallback(start, lineNumber, column, distance);
		AnimationUtils.executeSwingAnimationCallback(callback);
	}

	private int getOffscreenDistance(int line) {

		AnchoredLayout start = fieldPanel.getVisibleStartLayout();
		int visibleStartLine = start.getIndex().intValue();
		if (visibleStartLine > line) {
			// the end is off the top of the screen
			return visibleStartLine - line;
		}

		AnchoredLayout end = fieldPanel.getVisibleEndLayout();
		int visibleEndLine = end.getIndex().intValue();
		if (visibleEndLine < line) {
			// the end is off the bottom of the screen
			return line - visibleEndLine;
		}

		return 0;
	}

	void setSelection(ProgramSelection selection) {
		FieldSelection fieldSelection = null;
		if (selection == null || selection.isEmpty()) {
			fieldSelection = new FieldSelection();
		}
		else {
			List<ClangToken> tokens =
				DecompilerUtils.getTokens(layoutController.getRoot(), selection);
			fieldSelection = DecompilerUtils.getFieldSelection(tokens);
		}
		fieldPanel.setSelection(fieldSelection);
	}

	public void setDecompilerHoverProvider(DecompilerHoverProvider provider) {
		if (provider == null) {
			throw new IllegalArgumentException("Cannot set the hover handler to null!");
		}

		if (decompilerHoverProvider != null) {
			if (decompilerHoverProvider.isShowing()) {
				decompilerHoverProvider.closeHover();
			}
			decompilerHoverProvider.initializeListingHoverHandler(provider);
			decompilerHoverProvider.dispose();
		}
		decompilerHoverProvider = provider;
	}

	public void dispose() {
		setDecompileData(new EmptyDecompileData("Disposed"));
		layoutController = null;
		decompilerHoverProvider.dispose();
		highlighCursorUpdater.dispose();
		highlightController.dispose();
		highlightersById.clear();
	}

	public FontMetrics getFontMetrics() {
		Font font = options.getDefaultFont();
		return super.getFontMetrics(font);
	}

	private FontMetrics getFontMetrics(DecompileOptions decompileOptions) {
		Font font = decompileOptions.getDefaultFont();
		return getFontMetrics(font);
	}

	/**
	 * Passing false signals to disallow navigating to new functions from within the panel by using
	 * the mouse.
	 * 
	 * @param enabled false disabled mouse function navigation
	 */
	void setMouseNavigationEnabled(boolean enabled) {
		navitationEnabled = enabled;
	}

	@Override
	public void buttonPressed(FieldLocation location, Field field, MouseEvent ev) {
		if (!decompileData.hasDecompileResults()) {
			return;
		}

		int clickCount = ev.getClickCount();
		int buttonState = ev.getButton();

		if (buttonState == MouseEvent.BUTTON1) {
			if (DockingUtils.isControlModifier(ev) && clickCount == 2) {
				tryToGoto(location, field, ev, true);
			}
			else if (clickCount == 2) {
				tryToGoto(location, field, ev, false);
			}
			else if (DockingUtils.isControlModifier(ev) && ev.isShiftDown()) {
				controller.exportLocation();
			}
		}

		if (buttonState == middleMouseHighlightButton && clickCount == 1) {
			togglePrimaryHighlight(location, field, middleMouseHighlightColor);
		}
	}

	private void tryToGoto(FieldLocation location, Field field, MouseEvent event,
			boolean newWindow) {
		if (!navitationEnabled) {
			return;
		}

		ClangTextField textField = (ClangTextField) field;
		ClangToken token = textField.getToken(location);
		if (token instanceof ClangFuncNameToken) {
			tryGoToFunction((ClangFuncNameToken) token, newWindow);
		}
		else if (token instanceof ClangLabelToken) {
			tryGoToLabel((ClangLabelToken) token, newWindow);
		}
		else if (token instanceof ClangVariableToken) {
			tryGoToVarnode((ClangVariableToken) token, newWindow);
		}
		else if (token instanceof ClangCommentToken) {
			tryGoToComment(location, event, textField, newWindow);
		}
		else if (token instanceof ClangSyntaxToken) {
			tryGoToSyntaxToken((ClangSyntaxToken) token);
		}
	}

	private void tryGoToComment(FieldLocation location, MouseEvent event, ClangTextField textField,
			boolean newWindow) {

		// comments may use annotations; tell the annotation it was clicked
		FieldElement clickedElement = textField.getClickedObject(location);
		if (clickedElement instanceof AnnotatedTextFieldElement) {
			AnnotatedTextFieldElement annotation = (AnnotatedTextFieldElement) clickedElement;
			controller.annotationClicked(annotation, event, newWindow);
			return;
		}

		String text = textField.getText();
		String word = StringUtilities.findWord(text, location.col);
		tryGoToScalar(word, newWindow);
	}

	private void tryGoToFunction(ClangFuncNameToken functionToken, boolean newWindow) {
		Function function = DecompilerUtils.getFunction(controller.getProgram(), functionToken);
		if (function != null) {
			controller.goToFunction(function, newWindow);
			return;
		}

		// TODO no idea what this is supposed to be handling...someone doc this please
//		String labelName = functionToken.getText();
//		if (labelName.startsWith("func_0x")) {
//			try {
//				Address addr =
//					decompileData.getFunction().getEntryPoint().getAddress(labelName.substring(7));
//				controller.goToAddress(addr, newWindow);
//			}
//			catch (AddressFormatException e) {
//				controller.goToLabel(labelName, newWindow);
//			}
//		}
	}

	private void tryGoToLabel(ClangLabelToken token, boolean newWindow) {
		ClangNode node = token.Parent();
		if (node instanceof ClangStatement) {
			// check for a goto label
			ClangTokenGroup root = layoutController.getRoot();
			ClangLabelToken destination = DecompilerUtils.getGoToTargetToken(root, token);
			if (destination != null) {
				goToToken(destination);
				return;
			}
		}

		Address addr = token.getMinAddress();
		controller.goToAddress(addr, newWindow);
	}

	private void tryGoToSyntaxToken(ClangSyntaxToken token) {

		if (DecompilerUtils.isBrace(token)) {
			ClangSyntaxToken otherBrace = DecompilerUtils.getMatchingBrace(token);
			if (otherBrace != null) {
				goToToken(otherBrace);
			}
		}
	}

	private void tryGoToVarnode(ClangVariableToken token, boolean newWindow) {
		Varnode vn = token.getVarnode();
		if (vn == null) {
			PcodeOp op = token.getPcodeOp();
			if (op == null) {
				return;
			}
			int operation = op.getOpcode();
			if (!(operation == PcodeOp.PTRSUB || operation == PcodeOp.PTRADD)) {
				return;
			}
			vn = op.getInput(1);
			if (vn == null) {
				return;
			}

		}
		HighVariable highVar = vn.getHigh();
		if (highVar instanceof HighGlobal) {
			vn = highVar.getRepresentative();
		}
		if (vn.isAddress()) {
			Address addr = vn.getAddress();
			if (addr.isMemoryAddress()) {
				controller.goToAddress(vn.getAddress(), newWindow);
			}
		}
		else if (vn.isConstant()) {
			controller.goToScalar(vn.getOffset(), newWindow);
		}
	}

	private void tryGoToScalar(String text, boolean newWindow) {
		if (text.startsWith("0x")) {
			text = text.substring(2);
		}
		else if (text.startsWith("(") && text.endsWith(")")) {
			int commaIx = text.indexOf(",0x");
			if (commaIx < 2) {
				return;
			}
			String spaceName = text.substring(1, commaIx);
			String offsetStr = text.substring(commaIx + 3, text.length() - 1);
			try {
				AddressSpace space =
					decompileData.getProgram().getAddressFactory().getAddressSpace(spaceName);
				if (space == null) {
					return;
				}
				Address addr = space.getAddress(NumericUtilities.parseHexLong(offsetStr), true);
				controller.goToAddress(addr, newWindow);
			}
			catch (AddressOutOfBoundsException e) {
				// give-up
			}
			return;
		}
		try {
			long value = NumericUtilities.parseHexLong(text);
			controller.goToScalar(value, newWindow);
		}
		catch (NumberFormatException e) {
			return; // give up
		}
	}

	Program getProgram() {
		return decompileData.getProgram();
	}

	public ProgramLocation getCurrentLocation() {
		if (!decompileData.hasDecompileResults()) {
			return null;
		}
		Field currentField = fieldPanel.getCurrentField();
		FieldLocation cursorPosition = fieldPanel.getCursorLocation();
		return getProgramLocation(currentField, cursorPosition);
	}

	@Override
	public void fieldLocationChanged(FieldLocation location, Field field, EventTrigger trigger) {
		if (!decompileData.hasDecompileResults()) {
			return;
		}

		pendingHighlightUpdate = new PendingHighlightUpdate(location, field, trigger);
		highlighCursorUpdater.update();

		if (!(field instanceof ClangTextField)) {
			return;
		}

		ClangToken tok = ((ClangTextField) field).getToken(location);
		if (tok == null) {
			return;
		}

		// only broadcast when the user is clicking around
		if (trigger == EventTrigger.GUI_ACTION) {
			ProgramLocation programLocation = getProgramLocation(field, location);
			if (programLocation != null) {
				controller.locationChanged(programLocation);
			}
		}
	}

	@Override
	public void selectionChanged(FieldSelection selection, EventTrigger trigger) {
		if (clipboard != null) {
			clipboard.selectionChanged(selection);
		}
		if (!decompileData.hasDecompileResults()) {
			return;
		}
		if (trigger != EventTrigger.API_CALL) {
			Program program = decompileData.getProgram();
			Field[] lines = layoutController.getFields();
			List<ClangToken> tokenList = DecompilerUtils.getTokensInSelection(selection, lines);
			AddressSpace functionSpace = decompileData.getFunctionSpace();
			AddressSet addrset =
				DecompilerUtils.findClosestAddressSet(program, functionSpace, tokenList);
			ProgramSelection programSelection = new ProgramSelection(addrset);
			controller.selectionChanged(programSelection);
		}
	}

	@Override
	public void layoutsChanged(List<AnchoredLayout> layouts) {
		pixmap.layoutsChanged(layouts);
		for (DecompilerMarginProvider element : marginProviders) {
			element.setProgram(getProgram(), layoutController, pixmap);
		}
	}

	private ProgramLocation getProgramLocation(Field field, FieldLocation location) {
		if (!(field instanceof ClangTextField)) {
			return null;
		}
		ClangToken token = ((ClangTextField) field).getToken(location);
		if (token == null) {
			return null;
		}
		Address address = DecompilerUtils.getClosestAddress(getProgram(), token);
		if (address == null) {
			address = DecompilerUtils.findAddressBefore(layoutController.getFields(), token);
		}
		if (address == null) {
			address = decompileData.getFunction().getEntryPoint();
		}

		return new DecompilerLocation(decompileData.getProgram(), address,
			decompileData.getFunction().getEntryPoint(), decompileData.getDecompileResults(), token,
			location.getIndex().intValue(), location.col);
	}

//==================================================================================================
// Search Methods
//==================================================================================================

	public SearchLocation searchText(String text, FieldLocation startLocation,
			boolean forwardDirection) {
		return layoutController.findNextTokenForSearch(text, startLocation, forwardDirection);
	}

	public SearchLocation searchTextRegex(String text, FieldLocation startLocation,
			boolean forwardDirection) {
		return layoutController.findNextTokenForSearchRegex(text, startLocation, forwardDirection);
	}

	public void setSearchResults(SearchLocation searchLocation) {
		currentSearchLocation = searchLocation;
		repaint();
	}

	public FieldBasedSearchLocation getSearchResults() {
		return (FieldBasedSearchLocation) currentSearchLocation;
	}

//==================================================================================================
// End Search Methods
//==================================================================================================

	public Color getCurrentVariableHighlightColor() {
		return currentVariableHighlightColor;
	}

	public Color getMiddleMouseHighlightColor() {
		return middleMouseHighlightColor;
	}

	/**
	 * The color used in a primary highlight to mark the token that was clicked. This is used in
	 * 'slice' actions to mark the source of the slice.
	 * 
	 * @return the color
	 */
	public Color getSpecialHighlightColor() {
		return SPECIAL_COLOR_DEF;
	}

	public String getHighlightedText() {
		ClangToken token = highlightController.getHighlightedToken();
		if (token == null) {
			return null;
		}
		if (token instanceof ClangCommentToken) {
			return null; // comments are not single words that get highlighted
		}
		return token.getText();
	}

	public String getTextUnderCursor() {

		FieldLocation location = fieldPanel.getCursorLocation();
		ClangTextField textField = (ClangTextField) fieldPanel.getCurrentField();
		if (textField == null) {
			return null;
		}

		ClangToken token = textField.getToken(location);
		if (!(token instanceof ClangCommentToken)) {
			return token.getText(); // non-comment tokens are not multi-word; use the token's text
		}

		FieldElement clickedElement = textField.getClickedObject(location);
		if (clickedElement instanceof AnnotatedTextFieldElement) {
			AnnotatedTextFieldElement annotation = (AnnotatedTextFieldElement) clickedElement;
			return annotation.getDisplayString();
		}

		String text = textField.getText();
		return StringUtilities.findWord(text, location.col);
	}

	public String getSelectedText() {
		FieldSelection selection = fieldPanel.getSelection();
		if (selection.isEmpty()) {
			return null;
		}

		return FieldSelectionHelper.getFieldSelectionText(selection, fieldPanel);
	}

	public FieldLocation getCursorPosition() {
		return fieldPanel.getCursorLocation();
	}

	public void setCursorPosition(FieldLocation fieldLocation) {
		fieldPanel.setCursorPosition(fieldLocation.getIndex(), fieldLocation.getFieldNum(),
			fieldLocation.getRow(), fieldLocation.getCol());
		fieldPanel.scrollToCursor();
	}

	/**
	 * Returns a single selected token; null if there is no selection or multiple tokens selected.
	 * 
	 * @return a single selected token; null if there is no selection or multiple tokens selected.
	 */
	public ClangToken getSelectedToken() {
		FieldSelection selection = fieldPanel.getSelection();
		if (selection.isEmpty()) {
			return null;
		}

		Field[] lines = layoutController.getFields();
		List<ClangToken> tokens = DecompilerUtils.getTokensInSelection(selection, lines);

		long count = tokens.stream().filter(t -> !t.getText().trim().isEmpty()).count();
		if (count == 1) {
			return tokens.get(0);
		}
		return null;
	}

	public ClangToken getTokenAtCursor() {
		FieldLocation cursorPosition = fieldPanel.getCursorLocation();
		Field field = fieldPanel.getCurrentField();
		if (field == null) {
			return null;
		}
		return ((ClangTextField) field).getToken(cursorPosition);
	}

	/**
	 * Get the line number for the given y position, relative to the scroll panel
	 * 
	 * <p>
	 * If the y position is below all the lines, the last line is returned.
	 * 
	 * @param y the y position
	 * @return the line number, or 0 if not applicable
	 */
	public int getLineNumber(int y) {
		return pixmap.getIndex(y).intValue() + 1;
	}

	public DecompileOptions getOptions() {
		return options;
	}

	public void addHoverService(DecompilerHoverService hoverService) {
		decompilerHoverProvider.addHoverService(hoverService);
	}

	public void removeHoverService(DecompilerHoverService hoverService) {
		decompilerHoverProvider.removeHoverService(hoverService);
	}

	public void setHoverMode(boolean enabled) {
		decompilerHoverProvider.setHoverEnabled(enabled);
		if (enabled) {
			fieldPanel.setHoverProvider(decompilerHoverProvider);
		}
		else {
			fieldPanel.setHoverProvider(null);
		}
	}

	public boolean isHoverShowing() {
		return decompilerHoverProvider.isShowing();
	}

	public List<ClangToken> findTokensByName(String name) {
		List<ClangToken> tokens = new ArrayList<>();
		doFindTokensByName(tokens, layoutController.getRoot(), name);
		return tokens;
	}

	private void doFindTokensByName(List<ClangToken> tokens, ClangTokenGroup group, String name) {

		for (int i = 0; i < group.numChildren(); ++i) {
			ClangNode child = group.Child(i);
			if (child instanceof ClangTokenGroup) {
				doFindTokensByName(tokens, (ClangTokenGroup) child, name);
			}
			else if (child instanceof ClangToken) {
				ClangToken token = (ClangToken) child;
				if (name.equals(token.getText())) {
					tokens.add(token);
				}
			}
		}
	}

	public ViewerPosition getViewerPosition() {
		return fieldPanel.getViewerPosition();
	}

	public void setViewerPosition(ViewerPosition viewerPosition) {
		fieldPanel.setViewerPosition(viewerPosition.getIndex(), viewerPosition.getXOffset(),
			viewerPosition.getYOffset());
	}

	@Override
	public void requestFocus() {
		fieldPanel.requestFocus();
	}

	public void selectAll(EventTrigger trigger) {
		BigInteger numIndexes = layoutController.getNumIndexes();
		FieldSelection selection = new FieldSelection();
		selection.addRange(BigInteger.ZERO, numIndexes);
		fieldPanel.setSelection(selection, trigger);
	}

	public void optionsChanged(DecompileOptions decompilerOptions) {
		setBackground(decompilerOptions.getBackgroundColor());
		currentVariableHighlightColor = options.getCurrentVariableHighlightColor();
		middleMouseHighlightColor = decompilerOptions.getMiddleMouseHighlightColor();
		middleMouseHighlightButton = decompilerOptions.getMiddleMouseHighlightButton();
		searchHighlightColor = decompilerOptions.getSearchHighlightColor();

		highlightController.setHighlightColor(currentVariableHighlightColor);

		if (options.isDisplayLineNumbers()) {
			if (lineNumbersMargin == null) {
				addMarginProvider(lineNumbersMargin = new LineNumberDecompilerMarginProvider());
			}
		}
		else {
			if (lineNumbersMargin != null) {
				removeMarginProvider(lineNumbersMargin);
				lineNumbersMargin = null;
			}
		}

		for (DecompilerMarginProvider element : marginProviders) {
			element.setOptions(options);
		}
	}

	public void addMarginProvider(DecompilerMarginProvider provider) {
		marginProviders.add(0, provider);
		provider.setOptions(options);
		provider.setProgram(getProgram(), layoutController, pixmap);
		buildPanels();
	}

	public void removeMarginProvider(DecompilerMarginProvider provider) {
		marginProviders.remove(provider);
		buildPanels();
	}

	private void buildPanels() {
		removeAll();
		add(buildLeftComponent(), BorderLayout.WEST);
		add(scroller, BorderLayout.CENTER);
		add(taskMonitorComponent, BorderLayout.SOUTH);
	}

	private JComponent buildLeftComponent() {
		JPanel leftPanel = new JPanel(new ScrollpaneAlignedHorizontalLayout(scroller));
		for (DecompilerMarginProvider marginProvider : marginProviders) {
			leftPanel.add(marginProvider.getComponent());
		}
		return leftPanel;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class SearchHighlightFactory implements FieldHighlightFactory {

		@Override
		public Highlight[] createHighlights(Field field, String text, int cursorTextOffset) {
			if (currentSearchLocation == null) {
				return new Highlight[0];
			}

			ClangTextField cField = (ClangTextField) field;
			int highlightLine = cField.getLineNumber();

			FieldLocation searchCursorLocation =
				((FieldBasedSearchLocation) currentSearchLocation).getFieldLocation();
			int searchLineNumber = searchCursorLocation.getIndex().intValue() + 1;
			if (highlightLine != searchLineNumber) {
				// only highlight the match on the actual line
				return new Highlight[0];
			}

			return new Highlight[] { new Highlight(currentSearchLocation.getStartIndexInclusive(),
				currentSearchLocation.getEndIndexInclusive(), searchHighlightColor) };
		}
	}

	/**
	 * A simple class that handles the animators callback to scroll the display
	 */
	private class ScrollingCallback implements SwingAnimationCallback {

		private int startLine;
		private int endLine;
		private int endColumn;
		private int duration;

		ScrollingCallback(FieldLocation start, int endLineNumber, int endColumn, int distance) {
			this.startLine = start.getIndex().intValue();
			this.endLine = endLineNumber;
			this.endColumn = endColumn;

			// have things nearby execute more quickly so users don't wait needlessly
			double rate = Math.pow(distance, .8);
			int ms = (int) rate * 100;
			this.duration = Math.min(1000, ms);
		}

		@Override
		public int getDuration() {
			return duration;
		}

		@Override
		public void progress(double percentComplete) {

			int length = Math.abs(endLine - startLine);
			long offset = Math.round(length * percentComplete);
			int current = 0;
			if (startLine > endLine) {
				// backwards
				current = (int) (startLine - offset);
			}
			else {
				current = (int) (startLine + offset);
			}

			FieldLocation location = new FieldLocation(BigInteger.valueOf(current));
			fieldPanel.scrollTo(location);
		}

		@Override
		public void done() {
			fieldPanel.goTo(BigInteger.valueOf(endLine), 0, 0, endColumn, false);
		}
	}

	private class DecompilerFieldPanel extends FieldPanel {

		public DecompilerFieldPanel(LayoutModel model) {
			super(model);
		}

		/**
		 * Moves this field panel to the given line and column. Further, this navigation will fire
		 * an event to the rest of the tool. (This is in contrast to a field panel
		 * <code>goTo</code>, which we use to simply move the cursor, but not trigger an tool-level
		 * navigation event.)
		 * 
		 * @param lineNumber the line number
		 * @param column the column within the line
		 */
		void navigateTo(int lineNumber, int column) {
			fieldPanel.goTo(BigInteger.valueOf(lineNumber), 0, 0, column, false,
				EventTrigger.GUI_ACTION);
		}
	}

	/**
	 * A class to track pending location updates. This allows us to buffer updates, only sending the
	 * last one received.
	 */
	private class PendingHighlightUpdate {

		private FieldLocation location;
		private Field field;
		private EventTrigger trigger;
		private long updateId;

		PendingHighlightUpdate(FieldLocation location, Field field, EventTrigger trigger) {
			this.location = location;
			this.field = field;
			this.trigger = trigger;
			this.updateId = highlightController.getUpdateId();
		}

		void doUpdate() {

			// Note: don't send this buffered cursor change highlight if some other highlight
			//       has been applied.  Otherwise, this highlight would overwrite the last
			//       applied highlight.
			long lastUpdateId = highlightController.getUpdateId();
			if (updateId == lastUpdateId) {
				highlightController.fieldLocationChanged(location, field, trigger);
			}
		}
	}
}
