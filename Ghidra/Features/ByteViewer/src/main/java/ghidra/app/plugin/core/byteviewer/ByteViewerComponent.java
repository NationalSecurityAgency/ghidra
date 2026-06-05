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
package ghidra.app.plugin.core.byteviewer;

import java.awt.*;
import java.awt.event.*;
import java.math.BigInteger;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JToolTip;

import docking.*;
import docking.action.DockingActionIf;
import docking.actions.PopupActionProvider;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.listener.*;
import docking.widgets.fieldpanel.support.*;
import generic.theme.Gui;
import ghidra.app.plugin.core.format.*;
import ghidra.app.plugin.core.hover.AbstractHoverProvider;
import ghidra.app.services.HoverService;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;
import help.Help;
import help.HelpService;

/**
 * FieldViewer to show data formatted according to the DataFormatModel that is passed in to the
 * constructor. The source of the data is an array of ByteBlocks that is managed by an IndexMap.
 */
public class ByteViewerComponent extends FieldPanel
		implements FieldMouseListener, FieldLocationListener, FieldSelectionListener,
		FieldInputListener, PopupActionProvider, ByteViewerComponentNamer {

	private ByteViewerPanel panel;
	private DataFormatModel model;
	private int bytesPerLine;
	private FieldFactory[] fieldFactories;
	private FontMetrics fm;
	private int charWidth;
	private IndexMap indexMap;
	private ProgramByteBlockSet blockSet;

	private ByteViewerLayoutModel layoutModel;
	private boolean doingRefresh;
	private boolean doingEdit;
	private boolean updatingIndexMap;
	private boolean indexUpdate = true;
	private FieldLocation lastFieldLoc;

	private ByteViewerHighlighter highlightProvider = new ByteViewerHighlighter();

	private FieldSelectionListener liveSelectionListener = (selection, trigger) -> {
		ByteBlockSelection sel = processFieldSelection(selection);
		panel.updateLiveSelection(this, sel);
	};
	private ByteViewerHoverProvider byteViewerHoverProvider;

	/**
	 * Constructor
	 *
	 * @param panel the byte viewer panel that this component lives in
	 * @param layoutModel the layout model for this component
	 * @param model data format model that knows how the data should be displayed
	 * @param bytesPerLine number of bytes displayed in a row
	 */
	protected ByteViewerComponent(ByteViewerPanel panel, ByteViewerLayoutModel layoutModel,
			DataFormatModel model, int bytesPerLine) {
		super(layoutModel, "Byte Viewer");
		setFieldDescriptionProvider((l, f) -> getFieldDescription(l, f));

		this.panel = panel;
		this.model = model;
		this.bytesPerLine = bytesPerLine;
		this.layoutModel = layoutModel;

		setName(model.getName());
		getAccessibleContext().setAccessibleName("Byte Viewer " + model.getName());
		initialize();
	}

	private boolean isEditMode() {
		return panel.getEditMode();
	}

	private boolean isActiveComponent() {
		return panel.getCurrentComponent() == this;
	}

	private String getFieldDescription(FieldLocation fieldLoc, Field field) {
		if (field == null) {
			return null;
		}
		ByteBlockInfo info = indexMap.getBlockInfo(fieldLoc.getIndex(), fieldLoc.getFieldNum());
		if (info != null) {
			String modelName = model.getName();
			String location = getAccessibleLocationInfo(info.getBlock(), info.getOffset());
			return modelName + " format at " + location;
		}
		return null;
	}

	private String getAccessibleLocationInfo(ByteBlock block, BigInteger offset) {
		if (block instanceof MemoryByteBlock memBlock) {
			// location represents an address, remove leading zeros to make screen reading concise
			Address address = memBlock.getAddress(offset);
			return address.toString(address.getAddressSpace().showSpaceName(), 1);
		}
		// otherwise use generic location representation
		return block.getLocationRepresentation(offset);
	}

	@Override
	public String getByteViewerComponentName() {
		return model.getDescriptiveName();
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext context) {
		if (model instanceof PopupActionProvider popupProvider) {
			return popupProvider.getPopupActions(tool, context);
		}
		return null;
	}

	@Override
	public void buttonPressed(FieldLocation fieldLocation, Field field, MouseEvent mouseEvent) {
		if (fieldLocation == null || field == null) {
			return;
		}

		if (!(field instanceof ByteField)) {
			return;
		}

		if (mouseEvent.getButton() == panel.getHighlightButton()) {
			String text = field.getText();
			if (text.equals(highlightProvider.getText())) {
				highlightProvider.setText(null);
			}
			else {
				highlightProvider.setText(text);
			}
			repaint();
		}

		if (DockingUtils.isControlModifier(mouseEvent) && mouseEvent.isShiftDown() &&
			mouseEvent.getButton() == MouseEvent.BUTTON1) {
			fieldLocationChanged(fieldLocation, field, true, false);
		}
		else if (!isActiveComponent()) {
			// there was a click but the view wasn't the active view
			fieldLocationChanged(fieldLocation, field, false, true);
		}
	}

	@Override
	public void fieldLocationChanged(FieldLocation loc, Field field, EventTrigger trigger) {
		fieldLocationChanged(loc, field, false, trigger == EventTrigger.GUI_ACTION);
	}

	private void fieldLocationChanged(FieldLocation loc, Field field, boolean isAltDown,
			boolean setCurrentView) {
		// tell the panel that the location has changed
		if (doingRefresh || doingEdit || loc == null || indexMap == null || field == null ||
			updatingIndexMap) {
			return;
		}
		if (indexMap.isBlockSeparatorIndex(loc.getIndex())) {
			// special handling for non-byte mapped lines to insure other columns remain in sync
			panel.setCurrentNonMappedIndex(loc.getIndex(), this);
		}
		if (lastFieldLoc == null || !loc.getIndex().equals(lastFieldLoc.getIndex())) {
			// needed because the index column doesn't have a cursor that causes it to always
			// be repainted and have the ability to repaint the current line background
			panel.updateIndexColumnCurrentLine();
		}
		if (setCurrentView) {
			//Set this component as the current view in the panel
			panel.setCurrentView(this);
		}
		if (!(field instanceof ByteField) || (!isAltDown && loc.equals(lastFieldLoc))) {
			return;
		}

		// Update later because the field panel listener is called after this one, and sets the
		// colors incorrectly
		Swing.runLater(() -> updateColors());

		lastFieldLoc = loc;

		ByteField bf = (ByteField) field;
		int fieldOffset = bf.getFieldOffset();

		BigInteger index = loc.getIndex();
		int pos = loc.getCol();

		if (pos >= model.getDataUnitSymbolSize()) {
			pos = model.getDataUnitSymbolSize() - 1;
		}

		ByteBlockInfo info = indexMap.getBlockInfo(index, fieldOffset);
		if (info == null) {
			return;
		}

		ByteBlock block = info.getBlock();
		BigInteger offset = info.getOffset();
		int byteOffset = model.getByteOffset(info.getBlock(), pos);
		offset = offset.add(BigInteger.valueOf(byteOffset));
		panel.setInsertionField(this, block, offset, index, loc.getCol(), isAltDown);
	}

	/**
	 * Called whenever the FieldViewer selection changes.
	 */
	@Override
	public void selectionChanged(FieldSelection selection, EventTrigger trigger) {
		if (blockSet == null || doingRefresh) {
			return;
		}

		ByteBlockSelection sel = processFieldSelection(selection);

		// notify panel to update other components
		panel.updateSelection(this, sel);
		setViewerSelection(sel);
	}

	/**
	 * FieldInputListener method called to process key pressed event.
	 */
	@Override
	public void keyPressed(KeyEvent ev, BigInteger index, int fieldNum, int row, int col,
			Field field) {

		panel.setStatusMessage("");
		if (!isEditMode()) {
			return;
		}

		if (DockingUtils.isControlModifier(ev)) {
			// DO NOT consume here; let all modified keys go through (this lets undo/redo and the
			// like work)
			return;
		}

		if (ev.getKeyCode() == KeyEvent.VK_BACK_SPACE) {
			cursorLeft();
			ev.consume();
			return;
		}

		if (!(model instanceof MutableDataFormatModel mutableModel)) {
			panel.setStatusMessage(model.getName() + " view is not editable");
			ev.consume(); // we are in edit mode-don't let the event go through
			return;
		}

		char c = ev.getKeyChar();
		if (c < 0x20 || c > 0x7F) {
			ev.consume();
			getToolkit().beep();
			return;
		}

		if (field == null || !(field instanceof ByteField)) {
			ev.consume();
			getToolkit().beep();
			return;
		}

		int fieldOffset = ((ByteField) field).getFieldOffset();
		ByteBlockInfo info = indexMap.getBlockInfo(index, fieldOffset);
		if (info == null) {
			ev.consume();
			getToolkit().beep();
			return;
		}

		if (col >= model.getDataUnitSymbolSize()) {
			col = model.getDataUnitSymbolSize() - 1;
		}

		ByteBlock block = info.getBlock();
		if (!block.isEditable()) {
			panel.setStatusMessage("Block is not writable!");
			getToolkit().beep();
			ev.consume();
			return;
		}

		BigInteger offset = info.getOffset();
		// note: byte offset is handled by the model so we don't need
		// to add it in...
		int transactionID = blockSet.startTransaction();
		if (transactionID < 0) {
			ev.consume();
			getToolkit().beep();
			return;
		}
		try {
			byte[] oldValue = getByteValue(block, offset);
			boolean success = mutableModel.replaceValue(block, offset, col, c);
			if (success) {
				byte[] newValue = getByteValue(block, offset);
				blockSet.notifyByteEditing(block, offset, oldValue, newValue);
				// move the cursor
				cursorRight();
				doingEdit = true;
				layoutModel.dataChanged(index, index);
			}
			else {
				panel.setStatusMessage(
					"Invalid char '" + c + "' in the " + model.getName() + " view");
				getToolkit().beep();
			}
		}
		catch (ByteBlockAccessException | NumberFormatException exc) {
			panel.setStatusMessage("Editing not allowed: " + exc.getMessage());
			getToolkit().beep();

		}
		catch (AddressOutOfBoundsException | IndexOutOfBoundsException e) {
			getToolkit().beep();
		}
		catch (Throwable t) {
			Msg.showError(this, null, "Error", "Error editing memory", t);

		}
		finally {
			ev.consume();
			doingEdit = false;
			blockSet.endTransaction(transactionID, true);
		}
	}

	@Override
	public void setFont(Font font) {
		super.setFont(font);
		fm = getFontMetrics(getFont());
		if (model != null && layoutModel != null) {
			invalidateModelFields();
		}
	}

	void invalidateModelFields() {
		charWidth = model instanceof CursorWidthDataFormatModel cwdfm
				? cwdfm.getCursorWidth(fm)
				: fm.charWidth('W');
		createFields(); // redo the fields...
		layoutModel.setIndexMap(indexMap);
	}

	private byte[] getByteValue(ByteBlock block, BigInteger offset) {
		byte[] b = new byte[model.getUnitByteSize()];
		try {
			for (int i = 0; i < b.length; i++) {
				b[i] = block.getByte(offset.add(BigInteger.valueOf(i)));
			}
			return b;
		}
		catch (ByteBlockAccessException e) {
			// just return null
		}
		return null;
	}

	void addListeners() {
		addFieldLocationListener(this);
		addFieldSelectionListener(this);
		addLiveFieldSelectionListener(liveSelectionListener);
		addFieldInputListener(this);
		addFieldMouseListener(this);
	}

	void setIndexMap(IndexMap map) {
		updatingIndexMap = true;
		indexMap = map;
		if (map != null) {
			// remove fields and recreate them
			bytesPerLine = map.getBytesPerLine();
			createFields();
		}

		blockSet = indexMap.getByteBlockSet() instanceof ProgramByteBlockSet pbbs ? pbbs : null;
		byteViewerHoverProvider
				.setProgram(blockSet != null && blockSet.isValid() ? blockSet.program : null);
		if (indexUpdate) {
			layoutModel.setIndexMap(indexMap);
		}
		updatingIndexMap = false;
	}

	protected IndexMap getIndexMap() {
		return indexMap;
	}

	protected ProgramByteBlockSet getBlockSet() {
		return blockSet;
	}

	void setViewerSelection(ByteBlockSelection selection) {
		removeFieldSelectionListener(this);
		try {
			setSelection(getFieldSelection(selection));
		}
		catch (Exception e) {
			Msg.showError(this, null, "Error", "Error setting selection", e);
		}
		finally {
			addFieldSelectionListener(this);
		}
	}

	protected FieldSelection getFieldSelection(ByteBlockSelection selection) {
		FieldSelection fsel = new FieldSelection();
		for (int i = 0; i < selection.getNumberOfRanges(); i++) {
			ByteBlockRange r = selection.getRange(i);
			ByteBlock block = r.getByteBlock();
			BigInteger start = r.getStartIndex();
			BigInteger end = r.getEndIndex();

			FieldLocation startLoc = indexMap.getFieldLocation(block, start, fieldFactories);
			FieldLocation endLoc = indexMap.getFieldLocation(block, end, fieldFactories);

			// adjust the end index/field because the selection does not
			// include the end
			int endFieldOffset = endLoc.getFieldNum();
			BigInteger endIndex = endLoc.getIndex();

			if (endFieldOffset == fieldFactories.length - 1) {
				endFieldOffset = 0;
				endIndex = endIndex.add(BigInteger.ONE);
			}
			else {
				++endFieldOffset;
			}
			fsel.addRange(new FieldLocation(startLoc.getIndex(), startLoc.getFieldNum(), 0, 0),
				new FieldLocation(endIndex, endFieldOffset, 0, 0));
		}
		return fsel;
	}

	void setViewerHighlight(ByteBlockSelection highlight) {
		try {
			setHighlight(getFieldSelection(highlight));
		}
		catch (Exception e) {
			Msg.showError(this, null, "Error", "Error setting highlight", e);
		}
	}

	/**
	 * Set the cursor location; called in response to a location change event
	 *
	 * @param block the block
	 * @param index the index
	 * @param characterOffset the offset into the UI field
	 * @return index of the location; return -1 if there was an error setting the cursor location
	 */
	int setViewerCursorLocation(ByteBlock block, BigInteger index, int characterOffset) {
		if (indexMap == null) {
			return -1;
		}

		try {
			FieldLocation location = indexMap.getFieldLocation(block, index, fieldFactories);
			if (location == null) {
				return -1;
			}

			int column = adjustCharacterOffsetForBytesField(location, characterOffset);

			BigInteger fieldIndex = location.getIndex();
			int fieldNum = location.getFieldNum();
			int row = location.getRow();
			setCursorPosition(fieldIndex, fieldNum, row, column, EventTrigger.INTERNAL_ONLY);
			if (isActiveComponent()) {
				goTo(fieldIndex, fieldNum, row, column, false, EventTrigger.INTERNAL_ONLY);
			}

			return fieldIndex.intValue();
		}
		catch (AddressOutOfBoundsException e) {
			// just squash this; invalid location
		}
		catch (Exception e) {
			Msg.showError(this, null, "Error", "Error setting cursor location.", e);
		}

		return -1;
	}

	private int adjustCharacterOffsetForBytesField(FieldLocation fieldLoc, int characterOffset) {

		// Make sure the position is valid
		BigInteger index = fieldLoc.getIndex();
		if ((index.compareTo(BigInteger.ZERO) < 0) ||
			(index.compareTo(layoutModel.getNumIndexes()) >= 0)) {
			return characterOffset;
		}

		Layout layout = layoutModel.getLayout(index);
		if (layout == null) {
			return characterOffset;
		}

		int fieldNum = fieldLoc.getFieldNum();
		if (!(layout.getField(fieldNum) instanceof ByteField field)) {
			return characterOffset;
		}

		int column = Math.clamp(fieldLoc.getCol() + characterOffset, 0,
			field.getNumCols(fieldLoc.getRow()) - 1);
		return column;
	}

	/**
	 * Clear the selection.
	 */
	void clearViewerSelection() {
		removeFieldSelectionListener(this);
		clearSelection();
		addFieldSelectionListener(this);
	}

	/**
	 * Get the current selection.
	 *
	 * @return ByteBlockSelection selection, or null if there is no selection
	 */
	ByteBlockSelection getViewerSelection() {
		FieldSelection sel = getSelection();
		if (sel == null) {
			return null;
		}
		return processFieldSelection(sel);
	}

	/**
	 * Clear the highlight.
	 */
	void clearViewerHighlight() {
		clearHighlight();
	}

	/**
	 * Get the current highlight.
	 *
	 * @return ByteBlockSelection highlight, or null if there is no highlight
	 */
	ByteBlockSelection getViewerHighlight() {
		FieldSelection hl = getHighlight();
		if (hl == null) {
			return null;
		}
		return processFieldSelection(hl);
	}

	void returnToView(ByteBlock block, BigInteger index, ViewerPosition vpos) {
		FieldLocation fieldLoc = indexMap.getFieldLocation(block, index, fieldFactories);
		setViewerPosition(vpos.getIndex(), vpos.getXOffset(), vpos.getYOffset());
		setCursorPosition(fieldLoc.getIndex(), fieldLoc.getFieldNum(), fieldLoc.getRow(),
			fieldLoc.getCol());
	}

	/**
	 * Convert the cursor location to a byte block and an offset.
	 * @return the cursor location to a byte block and an offset.
	 */
	public ByteBlockInfo getViewerCursorLocation() {
		FieldLocation loc = getCursorLocation();
		if (loc == null) {
			ViewerPosition vp = getViewerPosition();
			if (vp == null) {
				return null;
			}
			return indexMap.getBlockInfo(vp.getIndex(), 0);
		}
		if (indexMap == null) {
			return null;
		}
		Field field = super.getCurrentField();
		if (!(field instanceof ByteField)) {
			return null;
		}
		ByteField currentField = (ByteField) field;
		int fieldOffset = currentField.getFieldOffset();
		int pos = loc.getCol();
		if (pos >= model.getDataUnitSymbolSize()) {
			pos = model.getDataUnitSymbolSize() - 1;
		}
		BigInteger index = loc.getIndex();
		ByteBlockInfo info = indexMap.getBlockInfo(index, fieldOffset);
		if (info == null) {
			return null;
		}
		BigInteger offset = info.getOffset();
		int byteOffset = model.getByteOffset(info.getBlock(), pos);
		offset = offset.add(BigInteger.valueOf(byteOffset));
		return new ByteBlockInfo(info.getBlock(), offset, loc.getCol());
	}

	DataFormatModel getDataModel() {
		return model;
	}

	private Color getActiveColor() {
		return isEditMode()
				? ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_EDIT
				: ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_NON_EDIT;
	}

	void updateColors() {
		setFocusedCursorColor(isActiveComponent()
				? getActiveColor()
				: ByteViewerComponentProvider.CURSOR_COLOR_UNFOCUSED_NON_EDIT);
	}

	/**
	 * Force the field model to refresh its data.
	 */
	void refreshView() {
		try {
			doingRefresh = true;
			FieldLocation loc = getCursorLocation();
			if (loc != null) {
				// get the selection before calling dataChanged()
				// on the layoutModel, because it clears the selection...
				ByteBlockSelection sel = getViewerSelection();
				layoutModel.dataChanged(loc.getIndex(), loc.getIndex());

				if (sel != null && sel.getNumberOfRanges() > 0) {
					setViewerSelection(sel);
				}
			}
		}
		finally {
			doingRefresh = false;
		}
	}

	@Override
	public void dispose() {
		super.dispose();
		model.dispose();
//    	scrollPane.getViewport().removeChangeListener(this);
		layoutModel.dispose();
		fieldFactories = null;
	}

	/**
	 * Set up colors and mouse listener.
	 */
	private void initialize() {
		setFont(ByteViewerComponentProvider.DEFAULT_FONT);

		createFields();

		setCursorOn(true);
		setNonFocusCursorColor(ByteViewerComponentProvider.CURSOR_COLOR_UNFOCUSED_NON_EDIT);
		setFocusedCursorColor(ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_NON_EDIT);

		addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				if (e.getButton() == MouseEvent.BUTTON3 && !isActiveComponent()) {
					// hack to make sure that a right-clicked component becomes the active
					// component
					panel.setCurrentView(ByteViewerComponent.this);
				}
			}
		});

		setBackgroundColor(ByteViewerComponentProvider.BG_COLOR);

		// specialized line coloring
		setBackgroundColorModel(new ByteViewerBGColorModel(panel));

		Gui.registerFont(this, ByteViewerComponentProvider.DEFAULT_FONT_ID);

		invalidateModelFields();

		enableHelp();

		byteViewerHoverProvider =
			new ByteViewerHoverProvider("ByteViewer" + model.getName() + "Hover");
		setHoverProvider(byteViewerHoverProvider);
	}

	@Override
	public boolean isDragging() { // open access 
		return super.isDragging();
	}

	/**
	 * Enable help for this component; used the model name as part of the help ID.
	 */
	private void enableHelp() {
		HelpService helpService = Help.getHelpService();
		if (helpService != null) {
			helpService.registerHelp(this, model.getHelpLocation());
		}
	}

	/**
	 * Create the fields.
	 */
	private void createFields() {

		int fieldCount = Math.max(bytesPerLine / model.getUnitByteSize(), 1);
		fieldFactories = new FieldFactory[fieldCount];
		int fieldOffset = 0;
		for (int i = 0; i < fieldCount; i++) {
			fieldFactories[i] = new FieldFactory(model, bytesPerLine, fieldOffset, charWidth, fm,
				highlightProvider);
			fieldOffset += model.getUnitByteSize();
			fieldFactories[i].setIndexMap(indexMap);
		}
		layoutModel.setFactorys(fieldFactories, model, charWidth);
	}

	private IndexedByteBlockInfo getBlockInfoForSelectionStart(FieldLocation loc) {
		BigInteger index = loc.getIndex();
		int fieldNum = loc.getFieldNum();

		// if the selection starts on a separator line, skip to the next beginning of the next line
		if (indexMap.isBlockSeparatorIndex(index)) {
			index = index.add(BigInteger.ONE);
			fieldNum = 0;
		}

		int offset = indexMap.getFieldOffset(index, fieldNum, fieldFactories);
		return indexMap.getBlockInfo(index, offset);
	}

	private IndexedByteBlockInfo getBlockInfoForSelectionEnd(FieldLocation loc) {
		BigInteger lineIndex = loc.getIndex();
		int fieldNum = loc.getFieldNum();

		// if the selection ends on a separator line, go back to the end of the previous line
		if (indexMap.isBlockSeparatorIndex(lineIndex)) {
			lineIndex = lineIndex.subtract(BigInteger.ONE);
			fieldNum = fieldFactories.length; // set to end of line factory
		}

		// if the selection is before the characters in this field, the selection doesn't include
		// this field, so move back a field. (Which may require moving back to the end of the
		// previous line)
		if (loc.getCol() == 0) {
			if (--fieldNum < 0) {
				lineIndex = lineIndex.subtract(BigInteger.ONE);
				if (indexMap.isBlockSeparatorIndex(lineIndex)) {
					lineIndex = lineIndex.subtract(BigInteger.ONE);
				}
				fieldNum = fieldFactories.length - 1; // set to end of line factory
			}
		}

		// get the byte offset for the first byte in the field
		int bytesFromLineStart = indexMap.getFieldOffset(lineIndex, fieldNum, fieldFactories);

		// extend the selection to include all bytes in the selected end field since we don't
		// currently support partial field selections
		int bytesInField = model.getUnitByteSize();
		int lastByteInSelectionOnLine = bytesFromLineStart + bytesInField - 1;

		return indexMap.getBlockInfo(lineIndex, lastByteInSelectionOnLine);
	}

	private void addByteBlockRange(ByteBlockSelection sel, IndexedByteBlockInfo start,
			IndexedByteBlockInfo end) {
		if (start == null || end == null) {
			return;
		}

		// this should only happen when both the start and end are on the same separator line
		if (start.compareTo(end) > 0) {
			return;
		}

		ByteBlock startBlock = start.getBlock();
		ByteBlock endBlock = end.getBlock();

		if (startBlock == endBlock) {
			ByteBlockRange r = new ByteBlockRange(startBlock, start.getOffset(), end.getOffset());
			sel.add(r);
		}
		else {
			BigInteger last = startBlock.getLength().subtract(BigInteger.ONE);
			sel.add(new ByteBlockRange(startBlock, start.getOffset(), last));
			sel.add(new ByteBlockRange(endBlock, BigInteger.ZERO, end.getOffset()));

			// collect the blocks that fall between the start and the
			for (ByteBlock byteBlock : indexMap.getBlocksBetween(start, end)) {
				BigInteger maxIndex = byteBlock.getLength().subtract(BigInteger.ONE);
				sel.add(new ByteBlockRange(byteBlock, BigInteger.ZERO, maxIndex));
			}
		}

	}

	/**
	 * Translates a screen/view selection into a byte block model selection
	 * @param fieldSelection a {@link FieldPanel} selection
	 * @return a {@link ByteBlockSelection}
	 */
	protected ByteBlockSelection processFieldSelection(FieldSelection fieldSelection) {

		ByteBlockSelection blockSelection = new ByteBlockSelection();
		int count = fieldSelection.getNumRanges();

		for (int i = 0; i < count; i++) {
			FieldRange range = fieldSelection.getFieldRange(i);
			IndexedByteBlockInfo start = getBlockInfoForSelectionStart(range.getStart());
			IndexedByteBlockInfo end = getBlockInfoForSelectionEnd(range.getEnd());
			addByteBlockRange(blockSelection, start, end);
		}

		return blockSelection;
	}

	String getTextForSelection() {
		FieldSelection selection = getSelection();
		if (selection == null) {
			return null;
		}

		return FieldSelectionHelper.getAllSelectedText(selection, this);
	}

	FieldLocation getFieldLocation(ByteBlock block, BigInteger offset) {
		return indexMap.getFieldLocation(block, offset, fieldFactories);
	}

	void enableIndexUpdate(boolean b) {
		indexUpdate = b;
	}

	////////////////////////////////////////////////////////////
	// for JUnit tests
	int getNumberOfFields() {
		return fieldFactories.length;
	}

	ByteField getField(BigInteger index, int fieldNum) {
		if (indexMap != null) {
			if (fieldNum < fieldFactories.length) {
				return (ByteField) fieldFactories[fieldNum].getField(index);
			}
		}
		return null;
	}

	public AddressSetView getView() {
		AddressSet result = new AddressSet();
		if (blockSet != null) {
			for (ByteBlock block : blockSet.getBlocks()) {
				Address start = blockSet.getBlockStart(block);
				result.add(start, start.add(block.getLength().longValue() - 1));
			}
		}
		return result;
	}

	/**
	 * Provides hover / tooltip popup for ByteViewer data models that implement
	 * {@link TooltipDataFormatModel}.
	 * <p>
	 * Typically HoverProviders rely on HoverServices (individually installed via plugins) that
	 * produce customized data for different components.  This class just hardwires everything
	 * together. 
	 */
	private class ByteViewerHoverProvider extends AbstractHoverProvider implements HoverService {

		public ByteViewerHoverProvider(String windowName) {
			super(windowName);
			addHoverService(this);
		}

		@Override
		protected ProgramLocation getHoverLocation(FieldLocation fieldLocation, Field field,
				Rectangle fieldBounds, MouseEvent event) {
			return model instanceof TooltipDataFormatModel && field instanceof ByteField
					? new ProgramLocation()
					: null;
		}

		@Override
		public int getPriority() {
			return 0;
		}

		@Override
		public boolean hoverModeSelected() {
			return true;
		}

		@Override
		public JComponent getHoverComponent(Program unusedProgram, ProgramLocation unusedProgLoc,
				FieldLocation fieldLocation, Field field) {

			if (!(field instanceof ByteField bf) ||
				!(model instanceof TooltipDataFormatModel ttdfm)) {
				return null;
			}
			BigInteger index = fieldLocation.getIndex();
			ByteBlockInfo info = indexMap.getBlockInfo(index, bf.getFieldOffset());

			if (info == null) {
				return null;
			}

			String ttStr =
				ttdfm.getTooltip(info.getBlock(), info.getOffset(), ByteViewerComponent.this);
			if (ttStr != null && !ttStr.isBlank()) {
				JToolTip tt = new JToolTip();
				tt.setTipText(ttStr);
				return tt;
			}
			return null;
		}

		@Override
		public void componentHidden() {
			// nothing
		}

		@Override
		public void componentShown() {
			// nothing
		}

		@Override
		public void scroll(int amount) {
			// WARNING: unusual situation.  This method signature is the same between both
			// AbstractHoverProvider and the HoverService interface.
			// AbstractHoverProvider calls the scroll() on the service, but when
			// both calls end up at the same method, you will get a stack overflow.
			// We implement a do-nothing here that prevents that.
		}
	}
}
