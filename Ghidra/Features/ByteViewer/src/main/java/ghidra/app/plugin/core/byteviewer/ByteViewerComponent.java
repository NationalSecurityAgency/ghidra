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

import java.awt.Color;
import java.awt.FontMetrics;
import java.awt.event.*;
import java.math.BigInteger;

import javax.swing.SwingUtilities;

import docking.DockingUtils;
import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.listener.*;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.plugin.core.format.*;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.util.Msg;

/**
 * FieldViewer to show data formatted according to the DataFormatModel that
 * is passed in to the constructor. The source of the data is an array
 * of ByteBlocks that is managed by an IndexMap.
 */
public class ByteViewerComponent extends FieldPanel implements FieldMouseListener,
		FieldLocationListener, FieldSelectionListener, FieldInputListener {

	private ByteViewerPanel panel;
	private DataFormatModel model;
	private int bytesPerLine;
	private FieldFactory[] fieldFactories;
	private FontMetrics fm;
	private IndexMap indexMap;
	private ProgramByteBlockSet blockSet;

	private boolean consumeKeyStrokes;
	private boolean editMode; // true if this component is in edit mode;
	// cursor is different color.
	private Color editColor;
	private Color currentCursorColor;
	private Color currentCursorLineColor;
	private ByteViewerLayoutModel layoutModel;
	private boolean doingRefresh;
	private boolean doingEdit;
	private boolean updatingIndexMap;
	private Runnable updateColorRunner;
	private boolean indexUpdate = true;
	private FieldLocation lastFieldLoc;

	private ByteViewerHighlightProvider highlightProvider;
	private int highlightButton = MouseEvent.BUTTON2;

	/**
	 * Constructor
	 * @param vpanel the byte viewer panel that this component lives in 
	 * @param layoutModel the layout model for this component
	 * @param model data format model that knows how the data should be
	 * 			displayed
	 * @param bytesPerLine number of bytes displayed in a row
	 * @param fm the font metrics used for drawing
	 */
	ByteViewerComponent(ByteViewerPanel vpanel, ByteViewerLayoutModel layoutModel,
			DataFormatModel model, int bytesPerLine, FontMetrics fm) {
		super(layoutModel);

		this.panel = vpanel;
		this.model = model;
		this.bytesPerLine = bytesPerLine;
		this.fm = fm;
		this.layoutModel = layoutModel;
		highlightProvider = new ByteViewerHighlightProvider();

		setName(model.getName());
		initialize();

		// specialized line coloring
		setBackgroundColorModel(new ByteViewerBackgroundColorModel());
	}

	@Override
	public void buttonPressed(FieldLocation fieldLocation, Field field, MouseEvent mouseEvent) {
		if (fieldLocation == null || field == null) {
			return;
		}

		if (!(field instanceof ByteField)) {
			return;
		}

		if (mouseEvent.getButton() == highlightButton) {
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
	}

	/**
	 * Called from the parent FieldPanel whenever the cursor position changes.
	 */
	@Override
	public void fieldLocationChanged(FieldLocation loc, Field field, EventTrigger trigger) {
		fieldLocationChanged(loc, field, false, trigger == EventTrigger.GUI_ACTION);
	}

	private void fieldLocationChanged(FieldLocation loc, Field field, boolean isAltDown,
			boolean setCurrentView) {
		// tell the panel that the location has changed
		// translate location
		if (doingRefresh || doingEdit || loc == null || indexMap == null || field == null ||
			updatingIndexMap) {
			return;
		}
		if (!(field instanceof ByteField) || (!isAltDown && loc.equals(lastFieldLoc))) {
			return;
		}
		if (setCurrentView) {
			//Set this component as the current view in the panel
			panel.setCurrentView(ByteViewerComponent.this);
		}
		// do the color update later because the field panel
		// listener is called after this one, and sets the
		// colors incorrectly
		SwingUtilities.invokeLater(updateColorRunner);

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
		if (!consumeKeyStrokes) {
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

		if (!model.isEditable()) {
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
			boolean success = model.replaceValue(block, offset, col, c);
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
		catch (ByteBlockAccessException exc) {
			panel.setStatusMessage("Editing not allowed: " + exc.getMessage());
			getToolkit().beep();

		}
		catch (AddressOutOfBoundsException e) {
			getToolkit().beep();
		}
		catch (IndexOutOfBoundsException e) {
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

	/**
	 * Add listeners.
	 */
	void addListeners() {
		addFieldLocationListener(this);
		addFieldSelectionListener(this);
		addFieldInputListener(this);
		addFieldMouseListener(this);
	}

	/**
	 * Set the FontMetrics; recreate the fields.
	 */
	void setFontMetrics(FontMetrics fm) {
		this.fm = fm;
		createFields();
		layoutModel.setIndexMap(indexMap);
	}

	/**
	 * Set the color used to denote changes in the byte block.
	 */
	void setEditColor(Color c) {
		editColor = c;
		for (FieldFactory fieldFactorie : fieldFactories) {
			fieldFactorie.setEditColor(c);
		}
		layoutModel.layoutChanged();
		updateColor();
	}

	void setHighlightButton(int highlightButton) {
		this.highlightButton = highlightButton;
	}

	void setMouseButtonHighlightColor(Color color) {
		highlightProvider.setHighlightColor(color);
	}

	/**
	 * Set the color for the component that has focus.
	 * @param c the color to set
	 */
	void setCurrentCursorColor(Color c) {
		currentCursorColor = c;
		updateColor();
	}

	/**
	 * Set the background color for the line containing the cursor.
	 * @param c the color to set
	 */
	void setCurrentCursorLineColor(Color c) {
		currentCursorLineColor = c;
	}

	/**
	 * Set the color for showing gaps in indexes.
	 * @param c the color to set
	 */
	void setSeparatorColor(Color c) {
		for (FieldFactory fieldFactorie : fieldFactories) {
			fieldFactorie.setSeparatorColor(c);
		}
		layoutModel.layoutChanged();
	}

	/**
	 * Get the color used to denote changes in the byte block.
	 */
	Color getEditColor() {
		return editColor;
	}

	/**
	 * Set the byte blocks for displaying data.
	 */
	void setIndexMap(IndexMap map) {
		updatingIndexMap = true;
		indexMap = map;
		if (map != null) {
			// remove fields and recreate them
			bytesPerLine = map.getBytesPerLine();
			createFields();
		}

		ByteBlockSet byteBlockSet = indexMap.getByteBlockSet();
		if (byteBlockSet instanceof ProgramByteBlockSet) {
			blockSet = (ProgramByteBlockSet) indexMap.getByteBlockSet();
		}
		else {
			blockSet = null;
		}
		if (indexUpdate) {
			layoutModel.setIndexMap(indexMap);
		}
		updatingIndexMap = false;
	}

	/**
	 * Set the new group size
	 * @param groupSize the group size
	 * @throws UnsupportedOperationException if model for this view does not support groups
	 */
	void setGroupSize(int groupSize) {
		model.setGroupSize(groupSize);
		createFields(); // redo the fields...
		layoutModel.setIndexMap(indexMap);
	}

	/**
	 * Set the selection.
	 */
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

	private FieldSelection getFieldSelection(ByteBlockSelection selection) {
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
			int endIndex = endLoc.getIndex().intValue();

			if (endFieldOffset == fieldFactories.length - 1) {
				endFieldOffset = 0;
				++endIndex;
			}
			else {
				++endFieldOffset;
			}
			fsel.addRange(
				new FieldLocation(startLoc.getIndex().intValue(), startLoc.getFieldNum(), 0, 0),
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
	 * @return index of the location; return -1 if there was an error
	 * setting the cursor location
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
			if (panel.getCurrentComponent() == this) {
				scrollToCursor();
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

		int column = characterOffset;
		int fieldNum = fieldLoc.getFieldNum();
		int fieldRow = fieldLoc.getRow();
		ByteField field = (ByteField) layout.getField(fieldNum);
		if (field != null) {
			// not sure this can be null
			int numCols = field.getNumCols(fieldRow);
			if (column >= numCols) {
				column = numCols - 1;
			}
		}

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

	/**
	 * Restore the view.
	 */
	void returnToView(ByteBlock block, BigInteger index, ViewerPosition vpos) {
		FieldLocation fieldLoc = indexMap.getFieldLocation(block, index, fieldFactories);
		setViewerPosition(vpos.getIndex(), vpos.getXOffset(), vpos.getYOffset());
		setCursorPosition(fieldLoc.getIndex(), fieldLoc.getFieldNum(), fieldLoc.getRow(),
			fieldLoc.getCol());
	}

	/**
	 * Convert the cursor location to a byte block and an offset.
	 */
	ByteBlockInfo getViewerCursorLocation() {
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
		ByteBlock block = info.getBlock();
		BigInteger offset = info.getOffset();
		int byteOffset = model.getByteOffset(info.getBlock(), pos);
		offset = offset.add(BigInteger.valueOf(byteOffset));
		return new ByteBlockInfo(block, offset, loc.getCol());
	}

	/**
	 * Get the data format model.
	 */
	DataFormatModel getDataModel() {
		return model;
	}

	/**
	 * Set the edit mode according to the given param if the model
	 * for this view supports editing.
	 * @param editMode true means to enable editing, and change the cursor
	 * color.
	 */
	void setEditMode(boolean editMode) {
		consumeKeyStrokes = editMode;
		if (!model.isEditable()) {
			return;
		}
		this.editMode = editMode;
		updateColor();
	}

	private void updateColor() {
		if (panel.getCurrentComponent() == this) {
			if (editMode) {
				setFocusedCursorColor(editColor);
			}
			else {
				setFocusedCursorColor(currentCursorColor);
			}
		}
	}

	/**
	 * Return true if this view is in edit mode.
	 */
	boolean getEditMode() {
		return editMode;
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
	}

	////////////////////////////////////////////////////////////////////////

	/**
	 * Set up colors and mouse listener.
	 */
	private void initialize() {
		createFields();

		setCursorOn(true);
		editColor = ByteViewerComponentProvider.DEFAULT_EDIT_COLOR;
		currentCursorColor = ByteViewerComponentProvider.DEFAULT_CURRENT_CURSOR_COLOR;
		setNonFocusCursorColor(ByteViewerComponentProvider.DEFAULT_NONFOCUS_CURSOR_COLOR);
		setFocusedCursorColor(currentCursorColor);

		updateColorRunner = () -> updateColor();

		addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				if (e.getButton() == MouseEvent.BUTTON3) {
					// hack to make sure that a right-clicked component becomes the active 
					// component
					panel.setCurrentView(ByteViewerComponent.this);
				}
			}
		});

		enableHelp();
	}

	/** 
	 * Enable help for this component; used the model name as part of
	 * the help ID.
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

		int fieldCount = bytesPerLine / model.getUnitByteSize();
		fieldFactories = new FieldFactory[fieldCount];
		int charWidth = fm.charWidth('W');
		int fieldOffset = 0;
		for (int i = 0; i < fieldCount; i++) {
			fieldFactories[i] =
				new FieldFactory(model, bytesPerLine, fieldOffset, fm, highlightProvider);
			fieldOffset += model.getUnitByteSize();
			fieldFactories[i].setEditColor(editColor);
			fieldFactories[i].setIndexMap(indexMap);
		}
		layoutModel.setFactorys(fieldFactories, model, charWidth);
	}

	private ByteBlockInfo getBlockInfo(FieldLocation loc, boolean isStart) {
		BigInteger index = loc.getIndex();
		int offset = indexMap.getFieldOffset(index, loc.getFieldNum(), fieldFactories);
		if (!isStart && loc.getCol() == 0) {
			offset--;
			if (offset < 0) {
				index = index.subtract(BigInteger.ONE);
				offset = indexMap.getFieldOffset(index, fieldFactories.length, fieldFactories);
				offset += model.getUnitByteSize() - 1;
			}
		}
		return indexMap.getBlockInfo(index, offset);
	}

	private void addByteBlockRange(ByteBlockSelection sel, ByteBlockInfo start, ByteBlockInfo end) {
		if (start == null || end == null) {
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
	 * Create a byte block selection from the field selection.
	 */
	private ByteBlockSelection processFieldSelection(FieldSelection selection) {

		ByteBlockSelection sel = new ByteBlockSelection();
		int count = selection.getNumRanges();

		for (int i = 0; i < count; i++) {
			FieldRange fr = selection.getFieldRange(i);
			ByteBlockInfo startInfo = getBlockInfo(fr.getStart(), true);
			ByteBlockInfo endInfo = getBlockInfo(fr.getEnd(), false);
			addByteBlockRange(sel, startInfo, endInfo);
		}

		return sel;
	}

	String getTextForSelection() {
		FieldSelection selection = getSelection();
		if (selection == null) {
			return null;
		}

		return FieldSelectionHelper.getAllSelectedText(selection, this);
	}

	/**
	 * Returns a field location for the given block, offset.
	 */
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
			int fieldOffset = indexMap.getFieldOffset(index, fieldNum, fieldFactories);
			if (fieldNum < fieldFactories.length) {
				return (ByteField) fieldFactories[fieldOffset].getField(index);
			}
		}
		return null;
	}

	private class ByteViewerBackgroundColorModel implements BackgroundColorModel {

		private Color defaultBackgroundColor = Color.WHITE;

		@Override
		public Color getBackgroundColor(BigInteger index) {
			if (indexIsInCurrentLine(index)) {
				return currentCursorLineColor;
			}

			return defaultBackgroundColor;
		}

		private boolean indexIsInCurrentLine(BigInteger layoutIndex) {
			Field currentField = getCurrentField();
			if (!(currentField instanceof ByteField)) {
				// empty field
				return false;
			}

			ByteField currentByteField = (ByteField) currentField;
			BigInteger currentIndex = currentByteField.getIndex();
			Layout layout = layoutModel.getLayout(layoutIndex);
			int n = layout.getNumFields();
			for (int i = 0; i < n; i++) {
				Field field = layout.getField(i);
				if (!(field instanceof ByteField)) {
					continue;
				}

				ByteField byteField = (ByteField) field;
				BigInteger fieldLayoutIndex = byteField.getIndex();
				if (fieldLayoutIndex.equals(currentIndex)) {
					return true;
				}
			}

			return false;
		}

		@Override
		public Color getDefaultBackgroundColor() {
			return defaultBackgroundColor;
		}

		@Override
		public void setDefaultBackgroundColor(Color c) {
			defaultBackgroundColor = c;
		}

	}
}
