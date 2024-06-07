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
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.field.EmptyTextField;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.listener.*;
import docking.widgets.fieldpanel.support.*;
import docking.widgets.indexedscrollpane.IndexedScrollPane;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import generic.theme.Gui;
import ghidra.app.plugin.core.format.*;
import ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.layout.PairLayout;
import help.Help;
import help.HelpService;

/**
 * Top level component that has a scrolled pane for the panel of components that show the
 * view for each format.
 */
public class ByteViewerPanel extends JPanel implements LayoutModel, LayoutListener {
	private static final String FONT_STATUS_ID = "font.byteviewer.status";
	private List<ByteViewerComponent> viewList; // list of field viewers
	private FieldPanel indexPanel; // panel for showing indexes
	private IndexFieldFactory indexFactory;
	private JLabel startField;
	private JLabel endField;
	private JLabel offsetField;
	private JLabel insertionField;
	private JPanel statusPanel;
	private int fontHeight;
	private FontMetrics fontMetrics;
	private int bytesPerLine;
	private ByteBlockSet blockSet;
	private ByteBlock[] blocks;
	private IndexMap indexMap; // maps indexes to the correct block and offset
	private int blockOffset;
	private ByteViewerComponent currentView;
	private Color editColor;
	private Color currentCursorColor;
	private Color currentCursorLineColor;
	private Color highlightColor;
	private int highlightButton;
	private List<LayoutModelListener> layoutListeners = new ArrayList<>(1);
	private boolean addingView; // don't respond to cursor location
	// changes while this flag is true
	private final ByteViewerComponentProvider provider;

	private List<AddressSetDisplayListener> displayListeners = new ArrayList<>();
	private ByteViewerIndexedView indexedView;

	protected ByteViewerPanel(ByteViewerComponentProvider provider) {
		super();
		this.provider = provider;
		bytesPerLine = ByteViewerComponentProvider.DEFAULT_BYTES_PER_LINE;
		viewList = new ArrayList<>();
		indexMap = new IndexMap();
		create();
		editColor = ByteViewerComponentProvider.CHANGED_VALUE_COLOR;
	}

	/**
	 * Return the size that this component would like to be.
	 */
	@Override
	public Dimension getPreferredSize() {

		Dimension dim = getSize();
		// calculate dimension
		int width = 0;
		int height = 20 * fontHeight + statusPanel.getHeight();
		if (dim != null) {
			height += dim.height;
		}
		boolean addHeight = true;
		for (int i = 0; i < viewList.size(); i++) {

			ByteViewerComponent c = viewList.get(i);
			Dimension d = c.getPreferredSize();
			width += d.width;
			width += 2; // for separator
			if (addHeight) {
				height += d.height;
				addHeight = false;
			}
		}

		if (width == 0) {
			width = statusPanel.getPreferredSize().width + 20; // add 20 for
			// border layout vertical gap
		}
		else {
			width += indexPanel.getPreferredSize().width;
		}
		return new Dimension(width, height);
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
	}

	//////////////////////////////////////////////////////////////////////////
	// ** package-level methods **
	//////////////////////////////////////////////////////////////////////////
	void setCurrentCursorColor(Color c) {
		currentCursorColor = c;
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent comp = viewList.get(i);
			comp.setCurrentCursorColor(c);
		}
	}

	void setCurrentCursorLineColor(Color c) {
		currentCursorLineColor = c;
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent comp = viewList.get(i);
			comp.setCurrentCursorLineColor(c);
		}
	}

	void setHighlightButton(int highlightButton) {
		this.highlightButton = highlightButton;
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent comp = viewList.get(i);
			comp.setHighlightButton(highlightButton);
		}
	}

	void setMouseButtonHighlightColor(Color color) {
		this.highlightColor = color;
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent comp = viewList.get(i);
			comp.setMouseButtonHighlightColor(color);
		}
	}

	void setCursorColor(Color c) {
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent comp = viewList.get(i);
			comp.setNonFocusCursorColor(c);
		}
	}

	void setSeparatorColor(Color c) {
		indexFactory.setMissingValueColor(c);
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent comp = viewList.get(i);
			comp.setSeparatorColor(c);
		}
	}

	void setNonFocusCursorColor(Color c) {
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent comp = viewList.get(i);
			comp.setNonFocusCursorColor(c);
		}
	}

	/**
	 * Set the byte blocks and create an new IndexMap object that will be passed to the index panel
	 * and to each component that shows a format.
	 * @param blockSet the set of blocks
	 */
	void setByteBlocks(ByteBlockSet blockSet) {
		this.blockSet = blockSet;
		blocks = null;
		indexMap = null;

		if (blockSet != null) {
			blocks = blockSet.getBlocks();
			if (blocks.length > 0) {
				indexMap = new IndexMap(blockSet, bytesPerLine, blockOffset);
				String start = blocks[0].getLocationRepresentation(BigInteger.ZERO);
				startField.setText(start);
				ByteBlock lastBlock = blocks[blocks.length - 1];
				endField.setText(lastBlock
						.getLocationRepresentation(lastBlock.getLength().subtract(BigInteger.ONE)));

				clearSelection();
			}
		}
		if (indexMap == null) {
			indexMap = new IndexMap();
		}
		indexFactory.setIndexMap(indexMap);
		indexFactory.setSize(getIndexSizeInChars());

		// Do the following loop twice - once with update off and then with update on.
		// need to do this because all the byte view components must have their models 
		// updated before any one of them tells their dependents about the change.
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.enableIndexUpdate(false);
			c.setIndexMap(indexMap);
		}
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.enableIndexUpdate(true);
			c.setIndexMap(indexMap);
		}
		if (blocks != null && blocks.length > 0) {
			indexedView.setIndexName(blocks[0].getIndexName());
		}
		indexPanel.dataChanged(BigInteger.ZERO, indexMap.getNumIndexes());
		indexSetChanged();
	}

	void setViewerSelection(ByteBlockSelection selection) {
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.setViewerSelection(selection);
		}
	}

	ByteBlockSelection getViewerSelection() {
		if (currentView == null) {
			return null;
		}
		return currentView.getViewerSelection();
	}

	void setViewerHighlight(ByteBlockSelection highlight) {
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.setViewerHighlight(highlight);
		}
	}

	public void setViewerBackgroundColorModel(BackgroundColorModel colorModel) {
		for (ByteViewerComponent c : viewList) {
			c.setBackgroundColorModel(colorModel);
		}
	}

	/**
	 * Get the current highlight.
	 *
	 * @return ByteBlockSelection highlight, or null if there is no highlight
	 */
	ByteBlockSelection getViewerHighlight() {
		if (currentView == null) {
			return null;
		}
		return currentView.getViewerHighlight();
	}

	/*
	 * Called by the plugin in response to an event. 
	 */
	void setCursorLocation(ByteBlock block, BigInteger index, int column) {

		int modelIndex = -1;
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			modelIndex = c.setViewerCursorLocation(block, index, column);
		}
		if (modelIndex >= 0) {
			insertionField.setText(block.getLocationRepresentation(index));
		}
	}

	/**
	 * Get the cursor location. If there is no current view, then return null.
	 * @return The ByteBlockInfo which describes the a location in the byte block domain
	 */
	ByteBlockInfo getCursorLocation() {
		if (currentView == null) {
			return null;
		}
		return currentView.getViewerCursorLocation();
	}

	/**
	 * Get the data format model of the view that is in focus.
	 *
	 * @return DataFormatModel model of the view in focus; return null if no views are shown
	 */
	DataFormatModel getCurrentModel() {
		if (currentView == null) {
			return null;
		}
		return currentView.getDataModel();
	}

	public ByteViewerComponent getCurrentComponent() {
		return currentView;
	}

	protected ByteViewerComponent newByteViewerComponent(DataFormatModel model) {
		return new ByteViewerComponent(this, new ByteViewerLayoutModel(), model, bytesPerLine,
			fontMetrics);
	}

	/**
	 * Add a view to the panel.
	 * 
	 * @param viewName name of the format, e.g., Hex, Ascii, etc.
	 * @param model model that understands the format
	 * @param editMode true if edit mode is on
	 * @param updateViewPosition true if the view position should be set
	 * @return the new component
	 */
	ByteViewerComponent addView(String viewName, DataFormatModel model, boolean editMode,
			boolean updateViewPosition) {

		if (viewList.size() != 0) {
			addingView = true;
		}
		final ViewerPosition vp = getViewerPosition();

		// create new ByteViewerComponent

		ByteViewerComponent c = newByteViewerComponent(model);
		c.setEditColor(editColor);
		c.setNonFocusCursorColor(ByteViewerComponentProvider.CURSOR_NOT_FOCUSED_COLOR);
		c.setCurrentCursorColor(currentCursorColor);
		c.setCurrentCursorLineColor(currentCursorLineColor);
		c.setEditMode(editMode);
		c.setIndexMap(indexMap);
		c.setMouseButtonHighlightColor(highlightColor);
		c.setHighlightButton(highlightButton);
		viewList.add(c);
		c.setSize(c.getPreferredSize());
		indexedView.addView(viewName, c);
		c.addListeners();

		if (viewList.size() == 1) {
			currentView = c;
			if (blocks != null) {
				setCursorLocation(blocks[0], BigInteger.ZERO, 0);
			}
		}
		else {
			ByteBlockSelection sel = currentView.getViewerSelection();
			if (sel != null) {
				c.setViewerSelection(sel);
			}

			ByteBlockSelection hl = currentView.getViewerHighlight();
			if (hl != null) {
				c.setViewerHighlight(hl);
			}

			ByteBlockInfo info = currentView.getViewerCursorLocation();
			if (info != null) {
				c.setViewerCursorLocation(info.getBlock(), info.getOffset(), info.getColumn());
			}
			if (updateViewPosition) {
				Runnable r = () -> indexPanel.setViewerPosition(vp.getIndex(), vp.getXOffset(),
					vp.getYOffset());
				SwingUtilities.invokeLater(r);
			}
			addingView = false;
		}
		validate();
		repaint();
		return c;
	}

	void removeView(ByteViewerComponent comp) {

		viewList.remove(comp);
		indexedView.removeView(comp);

		if (currentView == comp) {
			currentView = null;
		}

		if (viewList.size() > 0) {
			currentView = viewList.get(0);
		}
		comp.dispose();
		validate();
		repaint();
	}

	void setCurrentView(ByteViewerComponent c) {
		if (currentView != null && currentView != c) {
			currentView.setFocusedCursorColor(provider.getCursorColor());
		}
		currentView = c;
	}

	void setEditMode(boolean editMode) {
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.setEditMode(editMode);
		}
	}

	boolean getEditMode() {
		if (currentView == null) {
			return false;
		}
		return currentView.getEditMode();
	}

	/**
	 * Force the current view to be refreshed.
	 */
	void refreshView() {
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.refreshView();
		}
	}

	int getNumberOfViews() {
		return viewList.size();
	}

	void setOffset(int offset) {
		if (blockOffset != offset) {
			blockOffset = offset;
			updateIndexMap();
			offsetField.setText(Integer.toString(offset));
		}
	}

	void setBytesPerLine(int bytesPerLine) {

		if (this.bytesPerLine != bytesPerLine) {
			this.bytesPerLine = bytesPerLine;
			updateIndexMap();
		}
		// reset view column widths to preferred width for new bytesPerline
		indexedView.resetViewWidthToDefaults();

		// force everything to get validated, or else the
		// header columns do not get repainted properly...
		invalidate();
		validate();
		repaint();
	}

	/**
	 * Check that each model for the views can support the given bytes per line value.
	 * @param numBytesPerLine the bytes per line value to see if supported
	 * 
	 * @throws InvalidInputException if a model cannot support the bytesPerLine value
	 */
	void checkBytesPerLine(int numBytesPerLine) throws InvalidInputException {
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			DataFormatModel model = c.getDataModel();
			int groupSize = model.getGroupSize();
			if (groupSize > 0) {
				if (numBytesPerLine % groupSize != 0) {
					throw new InvalidInputException(
						"Bytes Per Line not divisible by Group Size[" + groupSize + "].");
				}
			}
		}
	}

	/**
	 * Set the group size on the current view.
	 * 
	 * @param groupSize new group size
	 */
	void setCurrentGroupSize(int groupSize) {
		if (currentView == null) {
			return;
		}
		ByteBlockInfo info = currentView.getViewerCursorLocation();
		currentView.setGroupSize(groupSize);
		if (info != null) {
			setCursorLocation(info.getBlock(), info.getOffset(), info.getColumn());
		}
		// force everything to get validated, or else the
		// header columns do not get repainted properly...

		invalidate();
		validate();
		repaint();
	}

	/**
	 * Set the insertion field and tell other views to change location; called when the
	 * ByteViewerComponent receives a notification that the cursor location has changed.
	 * 
	 * @param source source of the change
	 * @param block block for the new location
	 * @param offset offset into the block
	 * @param modelIndex the index in the model
	 * @param column the column position within the byte field (0-based)
	 * @param isAltDown true if the alt key is pressed
	 */
	void setInsertionField(ByteViewerComponent source, ByteBlock block, BigInteger offset,
			BigInteger modelIndex, int column, boolean isAltDown) {

		provider.updateLocation(block, offset, column, isAltDown);

		if (addingView) {
			return;
		}
		indexPanel.setCursorPosition(modelIndex, 0, 0, 0);
		if (block != null) {
			String locRep = block.getLocationRepresentation(offset);
			if (locRep == null) {
				return;
			}
			insertionField.setText(locRep);
		}
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			if (source == c) {
				continue;
			}
			c.setViewerCursorLocation(block, offset, column);
		}
	}

	/**
	 * Called from the ByteViewerComponent when it received a notification that the selection has
	 * changed.
	 * 
	 * @param source source of the change
	 * @param selection selection
	 */
	void updateSelection(ByteViewerComponent source, ByteBlockSelection selection) {
		provider.updateSelection(selection);

		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			if (source == c) {
				continue;
			}
			c.setViewerSelection(selection);
		}
	}

	FontMetrics getCurrentFontMetrics() {
		return fontMetrics;
	}

	List<String> getViewNamesInDisplayOrder() {
		return indexedView.getViewNamesInDisplayOrder();
	}

	/**
	 * Get the viewer position of the index panel.
	 *
	 * @return ViewerPosition top viewer position
	 */
	public ViewerPosition getViewerPosition() {
		return indexPanel.getViewerPosition();
	}

	public void setViewerPosition(ViewerPosition pos) {
		indexPanel.setViewerPosition(pos.getIndex(), pos.getXOffset(), pos.getYOffset());
	}

	void restoreView(ByteViewerState vp) {
		if (currentView == null) {
			return;
		}

		ByteBlock block = vp.getBlock();
		BigInteger offset = vp.getOffset();
		ViewerPosition vpos = vp.getViewerPosition();

		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.returnToView(block, offset, vpos);
		}
		indexPanel.setViewerPosition(vpos.getIndex(), vpos.getXOffset(), vpos.getYOffset());
	}

	/**
	 * Restore the configuration of the plugin.
	 * 
	 * @param metrics font metrics
	 * @param newEditColor color for showing edits
	 */
	void restoreConfigState(FontMetrics metrics, Color newEditColor) {
		setFontMetrics(metrics);
		setEditColor(newEditColor);
	}

	void restoreConfigState(int newBytesPerLine, int offset) {
		if (blockOffset != offset) {
			blockOffset = offset;
			offsetField.setText(Integer.toString(offset));
			if (this.bytesPerLine == newBytesPerLine) {
				updateIndexMap();
			}
		}
		setBytesPerLine(newBytesPerLine);
	}

	void programWasRestored() {
		updateIndexMap();
		refreshView();
	}

	void setFontMetrics(FontMetrics fm) {
		this.fontMetrics = fm;
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.setFontMetrics(fm);
		}
		indexFactory = new IndexFieldFactory(fm);
		indexFactory.setSize(getIndexSizeInChars());
		indexPanel.modelSizeChanged(IndexMapper.IDENTITY_MAPPER);
	}

	void setEditColor(Color editColor) {
		this.editColor = editColor;
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.setEditColor(editColor);
		}
	}

	protected FontMetrics getFontMetrics() {
		return fontMetrics;
	}

	protected int getBytesPerLine() {
		return bytesPerLine;
	}

	/**
	 * Create the components for this top level panel.
	 */
	private void create() {

		setLayout(new BorderLayout(10, 0));

		fontMetrics = getFontMetrics(Gui.getFont(ByteViewerComponentProvider.DEFAULT_FONT_ID));
		fontHeight = fontMetrics.getHeight();

		// for the index/address column
		indexFactory = new IndexFieldFactory(fontMetrics);
		indexPanel = new FieldPanel(this, "Byte Viewer");

		indexPanel.enableSelection(false);
		indexPanel.setCursorOn(false);
		indexPanel.setFocusable(false);
		indexPanel.addLayoutListener(this);

		indexedView = new ByteViewerIndexedView(indexPanel);
		IndexedScrollPane indexedScrollPane = new IndexedScrollPane(indexedView);
		indexedScrollPane.setWheelScrollingEnabled(false);
		indexedScrollPane.setColumnHeaderComp(indexedView.getColumnHeader());

		statusPanel = createStatusPanel();
		add(indexedScrollPane, BorderLayout.CENTER);
		add(statusPanel, BorderLayout.SOUTH);

		HelpService help = Help.getHelpService();
		help.registerHelp(this, new HelpLocation("ByteViewerPlugin", "ByteViewerPlugin"));
	}

	private JPanel createStatusPanel() {

		JLabel startLabel = new GLabel("Start:", SwingConstants.RIGHT);
		JLabel endLabel = new GLabel("End:", SwingConstants.RIGHT);
		JLabel offsetLabel = new GLabel("Offset:", SwingConstants.RIGHT);
		JLabel insertionLabel = new GLabel("Insertion:", SwingConstants.RIGHT);

		startField = new GDLabel("00000000");
		startField.setName("Start");

		endField = new GDLabel("00000000");
		endField.setName("End");

		offsetField = new GDLabel("00000000");
		offsetField.setName("Offset");

		insertionField = new GDLabel("00000000");
		insertionField.setName("Insertion");

		Gui.registerFont(startLabel, FONT_STATUS_ID);
		Gui.registerFont(endLabel, FONT_STATUS_ID);
		Gui.registerFont(offsetLabel, FONT_STATUS_ID);
		Gui.registerFont(insertionLabel, FONT_STATUS_ID);
		Gui.registerFont(startField, FONT_STATUS_ID);
		Gui.registerFont(endField, FONT_STATUS_ID);
		Gui.registerFont(offsetField, FONT_STATUS_ID);
		Gui.registerFont(insertionField, FONT_STATUS_ID);

		// make a panel for each label/value pair
		JPanel p1 = new JPanel(new PairLayout(0, 5));
		p1.add(startLabel);
		p1.add(startField);

		JPanel p2 = new JPanel(new PairLayout(0, 5));
		p2.add(endLabel);
		p2.add(endField);

		JPanel p3 = new JPanel(new PairLayout(0, 5));
		p3.add(offsetLabel);
		p3.add(offsetField);

		JPanel p4 = new JPanel(new PairLayout(0, 5));
		p4.add(insertionLabel);
		p4.add(insertionField);

		JPanel[] panels = { p1, p2, p3, p4 };

		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
		panel.add(Box.createHorizontalStrut(10));
		for (JPanel element : panels) {
			panel.add(element);
		}
		panel.add(Box.createHorizontalStrut(10));
		panel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
		return panel;
	}

	/**
	 * Create a new index map and update the map in the index field adapter and all the views.
	 */
	private void updateIndexMap() {
		if (blockSet == null) {
			return;
		}

		ByteBlockInfo info = null;
		if (currentView != null) {
			info = currentView.getViewerCursorLocation();
		}

		indexMap = new IndexMap(blockSet, bytesPerLine, blockOffset);
		indexFactory.setIndexMap(indexMap);
		ByteBlock block = null;
		BigInteger offset = BigInteger.ZERO;
		if (info != null) {
			block = info.getBlock();
			offset = info.getOffset();
		}
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.setIndexMap(indexMap);
			if (info != null) {
				c.setViewerCursorLocation(block, offset, info.getColumn());
			}
		}
		indexSetChanged();
	}

	/**
	 * Clear the selection.
	 */
	private void clearSelection() {
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.clearViewerSelection();
		}
	}

	@Override
	public boolean isUniform() {
		return true;
	}

	@Override
	public Dimension getPreferredViewSize() {
		// this is the preferred size of the address panel
		return new Dimension(100, 500);
	}

	@Override
	public BigInteger getNumIndexes() {
		if (indexMap == null) {
			return BigInteger.ZERO;
		}
		return indexMap.getNumIndexes();
	}

	@Override
	public Layout getLayout(BigInteger index) {
		Field field = indexFactory.getField(index);
		if (field == null) {
			int height = indexFactory.getMetrics().getMaxAscent() +
				indexFactory.getMetrics().getMaxDescent();
			field =
				new EmptyTextField(height, indexFactory.getStartX(), 0, indexFactory.getWidth());
		}
		return new SingleRowLayout(field);
	}

	@Override
	public void addLayoutModelListener(LayoutModelListener listener) {
		layoutListeners.add(listener);
	}

	@Override
	public void removeLayoutModelListener(LayoutModelListener listener) {
		layoutListeners.remove(listener);
	}

	void indexSetChanged() {
		for (LayoutModelListener listener : layoutListeners) {
			listener.modelSizeChanged(IndexMapper.IDENTITY_MAPPER);
		}
	}

	private int getIndexSizeInChars() {
		// set the field size at least the size of the column header name
		int minChars = ByteViewerComponentProvider.INDEX_COLUMN_NAME.length();
		if (blocks != null) {
			for (ByteBlock element : blocks) {
				int charCount = element.getMaxLocationRepresentationSize();
				minChars = Math.max(minChars, charCount);
			}
		}
		return minChars;
	}

	@Override
	public BigInteger getIndexAfter(BigInteger index) {
		BigInteger nextIndex = index.add(BigInteger.ONE);
		if (nextIndex.compareTo(indexMap.getNumIndexes()) >= 0) {
			return null;
		}
		return nextIndex;
	}

	@Override
	public BigInteger getIndexBefore(BigInteger index) {
		if (index.equals(BigInteger.ZERO)) {
			return null;
		}
		return index.subtract(BigInteger.ONE);
	}

	/***
	 * Getter for the list of ByteViewer Components
	 * 
	 * @return viewList the list of ByteViewerComponents
	 */
	public List<ByteViewerComponent> getViewList() {
		return viewList;
	}

	/**
	 * Set the status info on the tool.
	 * 
	 * @param message non-html text to display
	 */
	void setStatusMessage(String message) {
		provider.setStatusMessage(message);
	}

	@Override
	public void flushChanges() {
		// nothing to do
	}

	protected AddressSetView computeVisibleAddresses(List<AnchoredLayout> layouts) {
		// Kind of gross, but current component will do
		ByteViewerComponent component = getCurrentComponent();
		if (component == null || blockSet == null) {
			return new AddressSet();
		}

		BigInteger startIndex = layouts.get(0).getIndex();
		BigInteger endIndex = layouts.get(layouts.size() - 1).getIndex();
		FieldSelection fieldSel = new FieldSelection();
		fieldSel.addRange(startIndex, endIndex.add(BigInteger.ONE));
		ByteBlockSelection blockSel = component.processFieldSelection(fieldSel);
		return blockSet.getAddressSet(blockSel);
	}

	@Override
	public void layoutsChanged(List<AnchoredLayout> layouts) {
		AddressSetView visible = computeVisibleAddresses(layouts);
		for (AddressSetDisplayListener listener : displayListeners) {
			try {
				listener.visibleAddressesChanged(visible);
			}
			catch (Throwable t) {
				Msg.showError(this, indexPanel, "Error in Display Listener",
					"Exception encountered when notifying listeners of change in display", t);
			}
		}
	}

	public void addDisplayListener(AddressSetDisplayListener listener) {
		displayListeners.add(listener);
	}

	public void removeDisplayListener(AddressSetDisplayListener listener) {
		displayListeners.add(listener);
	}

	public int getViewWidth(String viewName) {
		return indexedView.getViewWidth(viewName);
	}

	public void setViewWidth(String viewName, int width) {
		indexedView.setColumnWidth(viewName, width);
	}
}
