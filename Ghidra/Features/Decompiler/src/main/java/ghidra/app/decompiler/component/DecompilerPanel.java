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

import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.DockingUtils;
import docking.widgets.EventTrigger;
import docking.widgets.SearchLocation;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.field.FieldElement;
import docking.widgets.fieldpanel.listener.*;
import docking.widgets.fieldpanel.support.*;
import docking.widgets.indexedscrollpane.IndexedScrollPane;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.hover.DecompilerHoverService;
import ghidra.app.plugin.core.decompile.DecompileClipboardProvider;
import ghidra.app.plugin.core.decompile.actions.FieldBasedSearchLocation;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.*;
import ghidra.util.bean.field.AnnotatedTextFieldElement;

/**
 * Class to handle the display of a decompiled function.
 */

public class DecompilerPanel extends JPanel implements FieldMouseListener, FieldLocationListener,
		FieldSelectionListener, ClangHighlightListener {

	private final static Color NON_FUNCTION_BACKGROUND_COLOR_DEF = new Color(220, 220, 220);

	// Default color for specially highlighted tokens
	private final static Color SPECIAL_COLOR_DEF = new Color(255, 100, 0, 128);

	private final DecompilerController controller;
	private final DecompileOptions options;

	private FieldPanel codeViewer;
	private ClangLayoutController layoutMgr;
	private HighlightFactory hlFactory;
	private ClangHighlightController highlightController;

	private int currentMiddleMouseHighlightButton;
	private Color currentSearchHighlightColor;
	private Color currentHighlightColor;
	private SearchLocation currentSearchLocation;

	private DecompileData decompileData = new EmptyDecompileData("No Function");
	private final DecompileClipboardProvider clipboard;

	private Color originalBackgroundColor;
	private boolean useNonFunctionColor = false;
	private boolean navitationEnabled = true;

	private DecompilerHoverProvider decompilerHoverProvider;

	DecompilerPanel(DecompilerController controller, DecompileOptions options,
			DecompileClipboardProvider clipboard, JComponent taskMonitorComponent) {
		this.controller = controller;
		this.options = options;
		this.clipboard = clipboard;
		FontMetrics metrics = getFontMetrics(options);
		if (clipboard != null) {
			clipboard.setFontMetrics(metrics);
		}
		hlFactory = new SearchHighlightFactory();

		layoutMgr = new ClangLayoutController(options, this, metrics, hlFactory);
		codeViewer = new FieldPanel(layoutMgr);
		setBackground(options.getCodeViewerBackgroundColor());

		IndexedScrollPane scroller = new IndexedScrollPane(codeViewer);
		codeViewer.addFieldSelectionListener(this);
		codeViewer.addFieldMouseListener(this);
		codeViewer.addFieldLocationListener(this);

		decompilerHoverProvider = new DecompilerHoverProvider();

		currentSearchHighlightColor = options.getSearchHighlightColor();
		currentHighlightColor = options.getMiddleMouseHighlightColor();
		currentMiddleMouseHighlightButton = options.getMiddleMouseHighlightButton();

		setLayout(new BorderLayout());
		add(scroller);
		add(taskMonitorComponent, BorderLayout.SOUTH);

		setPreferredSize(new Dimension(600, 400));
		setDecompileData(new EmptyDecompileData("No Function"));
	}

	public List<ClangLine> getLines() {
		return layoutMgr.getLines();
	}

	public List<Field> getFields() {
		return Arrays.asList(layoutMgr.getFields());
	}

	public FieldPanel getFieldPanel() {
		return codeViewer;
	}

	@Override
	public void setBackground(Color bg) {
		originalBackgroundColor = bg;
		if (useNonFunctionColor) {
			bg = NON_FUNCTION_BACKGROUND_COLOR_DEF;
		}
		if (codeViewer != null) {
			codeViewer.setBackgroundColor(bg);
		}
		super.setBackground(bg);
	}

	/**
	 * This function sets the current window display based
	 * on our display state.
	 */
	void setDecompileData(DecompileData decompileData) {
		if (layoutMgr == null) {
			// we've been disposed!
			return;
		}

		DecompileData oldData = this.decompileData;
		this.decompileData = decompileData;
		Function function = decompileData.getFunction();
		if (decompileData.hasDecompileResults()) {
			layoutMgr.buildLayouts(function, decompileData.getCCodeMarkup(), null, true);
			if (decompileData.getDebugFile() != null) {
				controller.setStatusMessage(
					"Debug file generated: " + decompileData.getDebugFile().getAbsolutePath());
			}
		}
		else {
			layoutMgr.buildLayouts(null, null, decompileData.getErrorMessage(), true);
		}

		setLocation(oldData, decompileData);

		decompilerHoverProvider.setProgram(decompileData.getProgram());

		/*
		 * Give user notice when seeing the decompile of a non-function.
		 */
		useNonFunctionColor = function instanceof UndefinedFunction;
		setBackground(originalBackgroundColor);
		if (clipboard != null) {
			clipboard.selectionChanged(null);
		}

		// don't highlight search results across functions
		currentSearchLocation = null;
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

	public LayoutModel getLayoutModel() {
		return layoutMgr;
	}

	public boolean containsLocation(ProgramLocation location) {
		return decompileData.contains(location);
	}

	public void setLocation(ProgramLocation location, ViewerPosition viewerPosition) {
		repaint();
		Address address = location.getAddress();
		if (address == null) {
			return;
		}
		if (viewerPosition != null) {
			codeViewer.setViewerPosition(viewerPosition.getIndex(), viewerPosition.getXOffset(),
				viewerPosition.getYOffset());
		}
		List<ClangToken> tokens =
			DecompilerUtils.getTokens(layoutMgr.getRoot(), translateAddress(address));

		if (location instanceof DecompilerLocation) {
			DecompilerLocation decompilerLocation = (DecompilerLocation) location;
			codeViewer.goTo(BigInteger.valueOf(decompilerLocation.getLineNumber()), 0, 0,
				decompilerLocation.getCharPos(), false);
		}
		else if (!tokens.isEmpty()) {
			int firstfield = DecompilerUtils.findIndexOfFirstField(tokens, layoutMgr.getFields());
			// Put cursor on first token in the list
			if (firstfield != -1) {
				codeViewer.goTo(BigInteger.valueOf(firstfield), 0, 0, 0, false);
			}
		}
	}

	/**
	 * Translate Ghidra address to decompiler address.
	 * Functions within an overlay space are decompiled
	 * in their physical space, therefore decompiler results
	 * refer to the functions underlying .physical space
	 * @param addr
	 * @return
	 */
	private Address translateAddress(Address addr) {
		Function func = decompileData.getFunction();
		if (func == null) {
			return addr;
		}
		AddressSpace funcSpace = func.getEntryPoint().getAddressSpace();
		if (funcSpace.isOverlaySpace() && addr.getAddressSpace().equals(funcSpace)) {
			return addr.getPhysicalAddress();
		}
		return addr;
	}

	/**
	 * Translate Ghidra address set to decompiler address set.
	 * Functions within an overlay space are decompiled
	 * in their physical space, therefore decompiler results
	 * refer to the functions underlying .physical space
	 * @param set
	 * @return
	 */
	private AddressSetView translateSet(AddressSetView set) {
		Function func = decompileData.getFunction();
		if (func == null) {
			return set;
		}
		AddressSpace funcSpace = func.getEntryPoint().getAddressSpace();
		if (!funcSpace.isOverlaySpace()) {
			return set;
		}
		AddressSet newSet = new AddressSet();
		AddressRangeIterator iter = set.getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			Address min = range.getMinAddress();
			if (min.getAddressSpace().equals(funcSpace)) {
				Address max = range.getMaxAddress();
				range = new AddressRangeImpl(min.getPhysicalAddress(), max.getPhysicalAddress());
			}
			newSet.add(range);
		}
		return newSet;
	}

	void setSelection(ProgramSelection selection) {
		FieldSelection fieldSelection = null;
		if (selection == null || selection.isEmpty()) {
			fieldSelection = new FieldSelection();
		}
		else {
			List<ClangToken> tokens =
				DecompilerUtils.getTokens(layoutMgr.getRoot(), translateSet(selection));
			fieldSelection = DecompilerUtils.getFieldSelection(tokens);
		}
		codeViewer.setSelection(fieldSelection);
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
		layoutMgr = null;

		decompilerHoverProvider.dispose();

	}

	private FontMetrics getFontMetrics(DecompileOptions decompileOptions) {
		Font font = decompileOptions.getDefaultFont();
		return getFontMetrics(font);
	}

	/**
	 * Passing false signals to disallow navigating to new functions from within the panel by 
	 * using the mouse.
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

		if (buttonState == currentMiddleMouseHighlightButton && clickCount == 1) {
			highlightVariable(location, field, currentHighlightColor);
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
			Function function =
				DecompilerUtils.getFunction(controller.getProgram(), (ClangFuncNameToken) token);
			if (function != null) {
				controller.goToFunction(function, newWindow);
			}
			else {
				String labelName = token.getText();
				if (labelName.startsWith("func_0x")) {
					try {
						Address addr = decompileData.getFunction().getEntryPoint().getAddress(
							labelName.substring(7));
						controller.goToAddress(addr, newWindow);
					}
					catch (AddressFormatException e) {
						controller.goToLabel(labelName, newWindow);
					}
				}
			}
		}
		else if (token instanceof ClangLabelToken) {
			Address addr = token.getMinAddress();
			controller.goToAddress(addr, newWindow);
		}
		else if (token instanceof ClangVariableToken) {
			tryGoToVarnode((ClangVariableToken) token, newWindow);
		}
		else if (token instanceof ClangCommentToken) {
			// special cases
			// -comments: these no longer use tokens for each item, but are one composite field
			FieldElement clickedElement = textField.getClickedObject(location);
			if (clickedElement instanceof AnnotatedTextFieldElement) {
				AnnotatedTextFieldElement annotation = (AnnotatedTextFieldElement) clickedElement;
				controller.annotationClicked(annotation, event, newWindow);
				return;
			}

			String text = clickedElement.getText();
			String word = StringUtilities.findWord(text, location.col);
			tryGoToScalar(word, newWindow);
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
			catch (Exception e) {
				// give-up
			}
			return;
		}
		try {
			long value = NumericUtilities.parseHexLong(text);
			controller.goToScalar(value, newWindow);
		}
		catch (Exception e) {
			return; // give up
		}
	}

	private void highlightVariable(FieldLocation location, Field field, Color highlightColor) {
		if (highlightController != null) {
			ClangToken token = ((ClangTextField) field).getToken(location);
			List<ClangToken> tokenList = new ArrayList<>();
			findTokensByName(tokenList, layoutMgr.getRoot(), token.getText());
			highlightController.clearHighlights();
			highlightController.addTokensToHighlights(tokenList, highlightColor);
			repaint();
		}
	}

	Program getProgram() {
		return decompileData.getProgram();
	}

	public ProgramLocation getCurrentLocation() {
		if (!decompileData.hasDecompileResults()) {
			return null;
		}
		Field currentField = codeViewer.getCurrentField();
		FieldLocation cursorPosition = codeViewer.getCursorLocation();
		return getProgramLocation(currentField, cursorPosition);
	}

	@Override
	public void fieldLocationChanged(FieldLocation location, Field field, EventTrigger trigger) {
		if (!decompileData.hasDecompileResults()) {
			return;
		}

		if (highlightController != null) {
			highlightController.fieldLocationChanged(location, field, trigger);
		}

		if (!(field instanceof ClangTextField)) {
			return;
		}

		ClangToken tok = ((ClangTextField) field).getToken(location);
		if (tok == null) {
			return;
		}

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
			Field[] lines = layoutMgr.getFields();
			List<ClangToken> tokenList = DecompilerUtils.getTokensInSelection(selection, lines);
			AddressSpace functionSpace = decompileData.getFunctionSpace();
			AddressSet addrset =
				DecompilerUtils.findClosestAddressSet(program, functionSpace, tokenList);
			ProgramSelection programSelection = new ProgramSelection(addrset);
			controller.selectionChanged(programSelection);
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
		Address address = DecompilerUtils.getClosestAddress(token);
		if (address == null) {
			address = DecompilerUtils.findAddressBefore(layoutMgr.getFields(), token);
		}
		if (address == null) {
			address = decompileData.getFunction().getEntryPoint();
		}

		// adjust in case function is in an overlay space.
		address = decompileData.getFunctionSpace().getOverlayAddress(address);

		return new DecompilerLocation(decompileData.getProgram(), address,
			decompileData.getFunction().getEntryPoint(), decompileData.getDecompileResults(), token,
			location.getIndex().intValue(), location.col);
	}

//==================================================================================================
// Search Methods
//==================================================================================================

	public SearchLocation searchText(String text, FieldLocation startLocation,
			boolean forwardDirection) {
		return layoutMgr.findNextTokenForSearch(text, startLocation, forwardDirection);
	}

	public SearchLocation searchTextRegex(String text, FieldLocation startLocation,
			boolean forwardDirection) {
		return layoutMgr.findNextTokenForSearchRegex(text, startLocation, forwardDirection);
	}

	public void setSearchResults(SearchLocation searchLocation) {
		currentSearchLocation = searchLocation;
		repaint();
	}

//==================================================================================================
// End Search Methods
//==================================================================================================

	public Color getDefaultHighlightColor() {
		return currentHighlightColor;
	}

	public Color getDefaultSpecialColor() {
		return SPECIAL_COLOR_DEF;
	}

	public String getHighlightedText() {
		if (highlightController != null) {
			return highlightController.getHighlightedText();
		}
		return null;
	}

	public FieldLocation getCursorPosition() {
		return codeViewer.getCursorLocation();
	}

	public void setCursorPosition(FieldLocation fieldLocation) {
		codeViewer.setCursorPosition(fieldLocation.getIndex(), fieldLocation.getFieldNum(),
			fieldLocation.getRow(), fieldLocation.getCol());
		codeViewer.scrollToCursor();
	}

	/**
	 * Returns a single selected token; null if there is no selection or multiple tokens selected.
	 * @return a single selected token; null if there is no selection or multiple tokens selected.
	 */
	public ClangToken getSelectedToken() {
		FieldSelection selection = codeViewer.getSelection();
		if (selection.isEmpty()) {
			return null;
		}

		Field[] lines = layoutMgr.getFields();
		List<ClangToken> tokens = DecompilerUtils.getTokensInSelection(selection, lines);

		long count = tokens.stream().filter(t -> !t.getText().trim().isEmpty()).count();
		if (count == 1) {
			return tokens.get(0);
		}
		return null;
	}

	public ClangToken getTokenAtCursor() {
		FieldLocation cursorPosition = codeViewer.getCursorLocation();
		Field field = codeViewer.getCurrentField();
		if (field == null) {
			return null;
		}
		return ((ClangTextField) field).getToken(cursorPosition);
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
			codeViewer.setHoverProvider(decompilerHoverProvider);
		}
		else {
			codeViewer.setHoverProvider(null);
		}
	}

	public boolean isHoverShowing() {
		return decompilerHoverProvider.isShowing();
	}

	public void clearHighlights() {
		if (highlightController != null) {
			highlightController.clearHighlights();
		}
	}

	public void addVarnodeHighlights(Set<Varnode> varnodes, Color highlightColor,
			Varnode specificvn, PcodeOp specificop, Color specialColor) {
		if (highlightController != null) {
			ClangTokenGroup root = layoutMgr.getRoot();
			highlightController.addVarnodesToHighlight(root, varnodes, highlightColor, specificvn,
				specificop, specialColor);
		}
	}

	public void addPcodeOpHighlights(Set<PcodeOp> ops, Color highlightColor) {
		if (highlightController != null) {
			ClangTokenGroup root = layoutMgr.getRoot();
			highlightController.addPcodeOpsToHighlight(root, ops, highlightColor);
		}
	}

	private void findTokensByName(List<ClangToken> tokenList, ClangTokenGroup group, String name) {
		for (int i = 0; i < group.numChildren(); ++i) {
			ClangNode child = group.Child(i);
			if (child instanceof ClangTokenGroup) {
				findTokensByName(tokenList, (ClangTokenGroup) child, name);
			}
			else if (child instanceof ClangToken) {
				ClangToken token = (ClangToken) child;
				if (name.equals(token.getText())) {
					tokenList.add(token);
				}
			}
		}
	}

	class SearchHighlightFactory implements HighlightFactory {

		@Override
		public Highlight[] getHighlights(Field field, String text, int cursorTextOffset) {
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
				currentSearchLocation.getEndIndexInclusive(), currentSearchHighlightColor) };
		}
	}

	public ViewerPosition getViewerPosition() {
		return codeViewer.getViewerPosition();
	}

	public void setViewerPosition(ViewerPosition viewerPosition) {
		codeViewer.setViewerPosition(viewerPosition.getIndex(), viewerPosition.getXOffset(),
			viewerPosition.getYOffset());
	}

	@Override
	public void requestFocus() {
		codeViewer.requestFocus();
	}

	public void selectAll() {
		BigInteger numIndexes = layoutMgr.getNumIndexes();
		FieldSelection selection = new FieldSelection();
		selection.addRange(BigInteger.ZERO, numIndexes);
		codeViewer.setSelection(selection);
		// fake it out that the selection was caused by the field panel GUI.
		selectionChanged(selection, EventTrigger.GUI_ACTION);
	}

	public void optionsChanged(DecompileOptions decompilerOptions) {
		setBackground(decompilerOptions.getCodeViewerBackgroundColor());
		currentHighlightColor = decompilerOptions.getMiddleMouseHighlightColor();
		currentMiddleMouseHighlightButton = decompilerOptions.getMiddleMouseHighlightButton();
		currentSearchHighlightColor = decompilerOptions.getSearchHighlightColor();
		if (highlightController != null) {
			highlightController.loadOptions(decompilerOptions);
		}
	}

	public void setHighlightController(ClangHighlightController highlightController) {
		this.highlightController = highlightController;
		highlightController.loadOptions(options);
		highlightController.addListener(this);
	}

	@Override
	public void tokenHighlightsChanged() {
		repaint();
	}

}
