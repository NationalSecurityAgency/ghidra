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
import javax.swing.event.*;

import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.field.EmptyTextField;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.listener.IndexMapper;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import docking.widgets.fieldpanel.support.SingleRowLayout;
import docking.widgets.fieldpanel.support.ViewerPosition;
import docking.widgets.indexedscrollpane.*;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.app.plugin.core.format.*;
import ghidra.util.HelpLocation;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.layout.HorizontalLayout;
import ghidra.util.layout.PairLayout;

/**
 * Top level component that contains has a scrolled pane for the panel of
 * components that show the view for each format.
 */
public class ByteViewerPanel extends JPanel implements TableColumnModelListener, LayoutModel {

//    private ByteViewerPlugin plugin;
	private List<ByteViewerComponent> viewList; // list of field viewers
	private FieldPanel indexPanel; // panel for showing indexes
	private IndexFieldFactory indexFactory;
	private JLabel startField;
	private JLabel endField;
	private JLabel offsetField;
	private JLabel insertionField;
	private JPanel statusPanel;
	private CompositePanel compPanel;
	private int fontHeight;
	private FontMetrics fm;
	private int bytesPerLine;
	private IndexedScrollPane scrollp;
	private ByteViewerHeader columnHeader;
	private ByteBlockSet blockSet;
	private ByteBlock[] blocks;
	private IndexMap indexMap; // maps indexes to the correct block and offset
	private int blockOffset;
	private ByteViewerComponent currentView;
	private Color editColor;
	private Color currentCursorColor;
	private Color cursorColor;
	private Color currentCursorLineColor;
	private Color highlightColor;
	private int highlightButton;
	private List<LayoutModelListener> layoutListeners = new ArrayList<>(1);
	private int indexPanelWidth;
	private boolean addingView; // don't respond to cursor location
	// changes while this flag is true
	private final ByteViewerComponentProvider provider;

	/**
	 * Constructor
	 */
	ByteViewerPanel(ByteViewerComponentProvider provider) {
		super();
		this.provider = provider;
		bytesPerLine = ByteViewerComponentProvider.DEFAULT_BYTES_PER_LINE;
		viewList = new ArrayList<>();
		indexMap = new IndexMap();
		create();
		editColor = ByteViewerComponentProvider.DEFAULT_EDIT_COLOR;
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

	// TableColumnModelListener interface methods
	@Override
	public void columnAdded(TableColumnModelEvent e) {
		// no-op
	}

	@Override
	public void columnMarginChanged(ChangeEvent e) {
		// no-op
	}

	/**
	 * Interface method called when the columns move.
	 */
	@Override
	public void columnMoved(TableColumnModelEvent e) {

		int fromIndex = e.getFromIndex();
		int toIndex = e.getToIndex();
		if (fromIndex == toIndex) {
			return;
		}
		compPanel.swapView(fromIndex, toIndex);

		invalidate();
		validate();
		repaint();
	}

	@Override
	public void columnRemoved(TableColumnModelEvent e) {
		// no-op
	}

	@Override
	public void columnSelectionChanged(ListSelectionEvent e) {
		// no-op
	}

	//////////////////////////////////////////////////////////////////////////
	// ** package-level methods **
	//////////////////////////////////////////////////////////////////////////
	/**
	 * Set the cursor color that indicates the view that has focus.
	 */
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
		cursorColor = c;
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent comp = viewList.get(i);
			comp.setNonFocusCursorColor(c);
		}
	}

	/**
	 * Set the color that indicates gaps in memory.
	 */
	void setSeparatorColor(Color c) {
		indexFactory.setMissingValueColor(c);
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent comp = viewList.get(i);
			comp.setSeparatorColor(c);
		}
	}

	/**
	 * Set the color of the cursor when the byte viewer is not in focus.
	 */
	void setNonFocusCursorColor(Color c) {
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent comp = viewList.get(i);
			comp.setNonFocusCursorColor(c);
		}
	}

	/**
	 * Set the byte blocks and create an new IndexMap object that will be
	 * passed to the index panel and to each component that shows a format.
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
				endField.setText(lastBlock.getLocationRepresentation(
					lastBlock.getLength().subtract(BigInteger.ONE)));

				indexPanelWidth = getIndexPanelWidth(blocks);
				int center = indexPanelWidth / 2;
				int startx = center - getMaxIndexSize() / 2;
				indexFactory.setStartX(startx);
				clearSelection();
			}
		}
		if (indexMap == null) {
			indexMap = new IndexMap();
		}
		indexFactory.setIndexMap(indexMap, indexPanelWidth);

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
			columnHeader.setColumnName(indexPanel, blocks[0].getIndexName());
			setCursorLocation(blocks[0], BigInteger.ZERO, 0);
		}
		indexPanel.dataChanged(BigInteger.ZERO, indexMap.getNumIndexes());
		indexSetChanged();
	}

	/**
	 * Set the selection for all the views.
	 */
	void setViewerSelection(ByteBlockSelection selection) {
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.setViewerSelection(selection);
		}
	}

	/**
	 * Get the current selection.
	 *
	 * @return ByteBlockSelection selection, or null if there is no selection
	 */
	ByteBlockSelection getViewerSelection() {
		if (currentView == null) {
			return null;
		}
		return currentView.getViewerSelection();
	}

	/**
	 * Set the highlight for all the views.
	 */
	void setViewerHighlight(ByteBlockSelection highlight) {
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.setViewerHighlight(highlight);
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
	 * @return DataFormatModel model of the view in focus; return null
	 * if no views are shown
	 */
	DataFormatModel getCurrentModel() {
		if (currentView == null) {
			return null;
		}
		return currentView.getDataModel();
	}

	/**
	 * Returns the currently focused view.
	 */
	ByteViewerComponent getCurrentComponent() {
		return currentView;
	}

	/**
	 * Add a view to the panel.
	 * @param viewName name of the format, e.g., Hex, Ascii, etc.
	 * @param model model that understands the format
	 * @param editMode true if edit mode is on
	 * @param updateViewPosition true if the view position should be
	 * set
	 */
	ByteViewerComponent addView(String viewName, DataFormatModel model, boolean editMode,
			boolean updateViewPosition) {

		if (viewList.size() != 0) {
			addingView = true;
		}
		final ViewerPosition vp = getViewerPosition();

		// create new ByteViewerComponent

		ByteViewerComponent c =
			new ByteViewerComponent(this, new ByteViewerLayoutModel(), model, bytesPerLine, fm);
		c.setEditColor(editColor);
		c.setNonFocusCursorColor(cursorColor);
		c.setCurrentCursorColor(currentCursorColor);
		c.setCurrentCursorLineColor(currentCursorLineColor);
		c.setEditMode(editMode);
		c.setIndexMap(indexMap);
		c.setMouseButtonHighlightColor(highlightColor);
		c.setHighlightButton(highlightButton);
		viewList.add(c);
		c.setSize(c.getPreferredSize());
		compPanel.addByteViewerComponent(c);
		// tell column header it needs to grow
		columnHeader.addColumn(viewName, c);

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

	/**
	 * Remove the view that currently has focus.
	 */
	void removeView(ByteViewerComponent comp) {

		viewList.remove(comp);
		compPanel.removeByteViewerComponent(comp);
		columnHeader.removeColumn(comp);

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

	/**
	 * Set the given component to be the current view; called by the
	 * mouse listener in the ByteViewerComponent when the user clicks in the
	 * panel.
	 */
	void setCurrentView(ByteViewerComponent c) {
		if (currentView != null && currentView != c) {
			currentView.setFocusedCursorColor(provider.getCursorColor());
		}
		currentView = c;
	}

	/**
	 * Set the cursor color on the current view to show that it is in
	 * edit mode.
	 */
	void setEditMode(boolean editMode) {
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.setEditMode(editMode);
		}
	}

	/**
	 * Return true if the current view is in edit mode.
	 *
	 */
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
//        PluginEvent lastSelectionEvent = plugin.getLastSelectionEvent();
//        if (lastSelectionEvent != null) {
//            plugin.firePluginEvent(lastSelectionEvent);
//        }
	}

	/**
	 * Get the number of views that is currently displayed.
	 */
	int getNumberOfViews() {
		return viewList.size();
	}

	/**
	 * Set the block offset.
	 */
	void setOffset(int offset) {
		if (blockOffset != offset) {
			blockOffset = offset;
			updateIndexMap();
			offsetField.setText(Integer.toString(offset));
		}
	}

	/**
	 * Set the bytes per line. Bytes per line dictates the number of fields
	 * displayed in a row.
	 */
	void setBytesPerLine(int bytesPerLine) {

		if (this.bytesPerLine != bytesPerLine) {
			this.bytesPerLine = bytesPerLine;
			updateIndexMap();
		}
		// force everything to get validated, or else the
		// header columns do not get repainted properly...

		invalidate();
		validate();
		repaint();
	}

	/**
	 * Check that each model for the views can support the given
	 * bytes per line value.
	 * @throws InvalidInputException if a model cannot support the
	 * bytesPerLine value
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
	 * Set the insertion field and tell other views to change location;
	 * called when the ByteViewerComponent receives a notification that
	 * the cursor location has changed.
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
	 * Called from the ByteViewerComponent when it received a notification
	 * that the selection has changed.
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

	/**
	 * Get the font metrics that all viewer components are using.
	 */
	FontMetrics getCurrentFontMetrics() {
		return fm;
	}

	/**
	 * Return array of names of views in the order that they appear in the
	 * panel. The name array includes an entry for the index panel.
	 */
	DataModelInfo getDataModelInfo() {

		DataModelInfo info = new DataModelInfo(viewList.size());
		Component[] c = compPanel.getComponents();
		int index = 0;
		for (Component element : c) {
			if (element instanceof JSeparator) {
				continue;
			}
			if (element == indexPanel) {
				// don't put the index panel into the data model info, as it is not configurable
				continue;
			}
			else if (element instanceof ByteViewerComponent) {
				DataFormatModel model = ((ByteViewerComponent) element).getDataModel();
				String name = model.getName();
				int groupSize = model.getGroupSize();
				info.set(index, name, groupSize);
				++index;
			}
		}
		return info;
	}

	/**
	 * Get the viewer position of the index panel.
	 *
	 * @return ViewerPosition top viewer position
	 */
	ViewerPosition getViewerPosition() {
		return indexPanel.getViewerPosition();
	}

	void setViewerPosition(ViewerPosition pos) {
		indexPanel.setViewerPosition(pos.getIndex(), pos.getXOffset(), pos.getYOffset());
	}

	/**
	 * Restore the view.
	 */
	void returnToView(ByteViewerState vp) {
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
	 * @param fontMetrics font metrics
	 * @param newEditColor color for showing edits
	 */
	void restoreConfigState(FontMetrics fontMetrics, Color newEditColor) {
		setFontMetrics(fontMetrics);
		setEditColor(newEditColor);
	}

	/**
	 * Restore the bytes per line and offset values.
	 */
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

	/**
	 * Set the font metrics.
	 */
	void setFontMetrics(FontMetrics fm) {
		this.fm = fm;
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.setFontMetrics(fm);
		}
		indexFactory = new IndexFieldFactory(fm);

		int charWidth = fm.charWidth('W');
		indexFactory.setStartX(charWidth);
		indexPanelWidth =
			ByteViewerComponentProvider.DEFAULT_NUMBER_OF_CHARS * charWidth + (2 * charWidth);
		if (blocks != null) {
			indexPanelWidth = getIndexPanelWidth(blocks);
		}
		indexFactory.setIndexMap(indexMap, indexPanelWidth);
		indexPanel.modelSizeChanged(IndexMapper.IDENTITY_MAPPER);
	}

	/**
	 * Set the color used to denote changes in the byte block.
	 */
	void setEditColor(Color editColor) {
		this.editColor = editColor;
		for (int i = 0; i < viewList.size(); i++) {
			ByteViewerComponent c = viewList.get(i);
			c.setEditColor(editColor);
		}
	}

	/**
	 * Get the font metrics that the panel is using.
	 */
	FontMetrics getFontMetrics() {
		return fm;
	}

	/**
	 * Create the components for this top level panel.
	 */
	private void create() {

		setLayout(new BorderLayout(10, 0));

		columnHeader = new ByteViewerHeader(this);

		fm = getFontMetrics(ByteViewerComponentProvider.DEFAULT_FONT);
		fontHeight = fm.getHeight();

		// for the index/address column
		indexFactory = new IndexFieldFactory(fm);
		indexPanel = new FieldPanel(this);

		indexPanel.enableSelection(false);
		indexPanel.setCursorOn(false);
		indexPanel.setFocusable(false);

		compPanel = new CompositePanel(indexPanel);

		scrollp = new IndexedScrollPane(compPanel);
		scrollp.setWheelScrollingEnabled(false);

		columnHeader = new ByteViewerHeader(this);
		columnHeader.addColumnModelListener(this);

		columnHeader.addColumn(ByteViewerComponentProvider.DEFAULT_INDEX_NAME, indexPanel);
		scrollp.setColumnHeaderComp(columnHeader);
		compPanel.setBackground(Color.WHITE);

		statusPanel = createStatusPanel();
		add(scrollp, BorderLayout.CENTER);
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

		Font f = new Font("SansSerif", Font.PLAIN, 11);
		startLabel.setFont(f);
		endLabel.setFont(f);
		offsetLabel.setFont(f);
		insertionLabel.setFont(f);
		startField.setFont(f);
		endField.setFont(f);
		offsetField.setFont(f);
		insertionField.setFont(f);

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
	 * Create a new index map and update the map in the index field adapter
	 * and all the views.
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
		indexPanelWidth = getIndexPanelWidth(blocks);
		indexFactory.setIndexMap(indexMap, indexPanelWidth);
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
		return new Dimension(indexPanelWidth, 500);
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

	private int getIndexPanelWidth(ByteBlock[] blocks1) {
		FontMetrics headerFm = columnHeader.getFontMetrics(columnHeader.getFont());
		String indexName = ByteViewerComponentProvider.DEFAULT_INDEX_NAME;
		if (blocks1.length > 0) {
			indexName = blocks1[0].getIndexName();
		}
		int nameWidth = headerFm.stringWidth(indexName);
		int charWidth = fm.charWidth('W');
		return Math.max(nameWidth, getMaxIndexSize() + 2 * charWidth);
	}

	private int getMaxIndexSize() {
		int maxWidth = 0;
		int charWidth = fm.charWidth('W');
		for (ByteBlock element : blocks) {
			int width = element.getMaxLocationRepresentationSize() * charWidth;
			maxWidth = Math.max(maxWidth, width);
		}

		return maxWidth;
	}

	/**
	 * @see docking.widgets.fieldpanel.LayoutModel#getIndexAfter(int)
	 */
	@Override
	public BigInteger getIndexAfter(BigInteger index) {
		BigInteger nextIndex = index.add(BigInteger.ONE);
		if (nextIndex.compareTo(indexMap.getNumIndexes()) >= 0) {
			return null;
		}
		return nextIndex;
	}

	/**
	 * @see docking.widgets.fieldpanel.LayoutModel#getIndexBefore(int)
	 */
	@Override
	public BigInteger getIndexBefore(BigInteger index) {
		if (index.equals(BigInteger.ZERO)) {
			return null;
		}
		return index.subtract(BigInteger.ONE);
	}

	/**
	 * @see docking.widgets.fieldpanel.LayoutModel#changePending()
	 */
	public boolean changePending() {
		return false;
	}

	/***
	 * Getter for the list of ByteViewer Components
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
}

class CompositePanel extends JPanel implements IndexedScrollable, IndexScrollListener {
	FieldPanel indexPanel;
	BoundedRangeModel verticalScrollBarModel;
	BoundedRangeModel horizontalScrollBarModel;
	List<ByteViewerComponent> viewList = new ArrayList<>();
	List<FieldPanel> allPanels = new ArrayList<>();
	private boolean processingIndexRangeChanged;

	CompositePanel(FieldPanel indexPanel) {
		super(new HorizontalLayout(0));
		this.indexPanel = indexPanel;
		indexPanel.addIndexScrollListener(this);
		addMouseWheelListener(e -> {
			// this lets us scroll the byte viewer when the user is not over any panel, but still over the view
			Layout firstLayout = indexPanel.getLayoutModel().getLayout(BigInteger.ZERO);
			int layoutScrollHt = firstLayout != null //
					? firstLayout.getScrollableUnitIncrement(0, 1)
					: 0;

			double wheelRotation = e.getPreciseWheelRotation();
			int scrollAmount =
				(int) (wheelRotation * layoutScrollHt * FieldPanel.MOUSEWHEEL_LINES_TO_SCROLL);

			indexPanel.scrollView(scrollAmount);
			e.consume();
		});

		allPanels.add(indexPanel);
		rebuildPanels();
	}

	public void swapView(int fromIndex, int toIndex) {
		FieldPanel from = allPanels.get(fromIndex);
		FieldPanel to = allPanels.get(toIndex);
		allPanels.set(fromIndex, to);
		allPanels.set(toIndex, from);
		rebuildPanels();
	}

	void addByteViewerComponent(ByteViewerComponent comp) {
		comp.addIndexScrollListener(this);
		viewList.add(comp);
		allPanels.add(comp);
		rebuildPanels();
	}

	void removeByteViewerComponent(ByteViewerComponent comp) {
		comp.removeIndexScrollListener(this);
		viewList.remove(comp);
		allPanels.remove(comp);
		rebuildPanels();
	}

	private void rebuildPanels() {
		removeAll();
		int count = 0;
		for (FieldPanel panel : allPanels) {
			if (count++ != 0) {
				super.add(new JSeparator(SwingConstants.VERTICAL));
			}
			super.add(panel);
		}
//		setSize(getPreferredSize());
		invalidate();
	}

	@Override
	public Component add(Component comp) {
		throw new UnsupportedOperationException("External call to add(Component) not allowed");
	}

	@Override
	public void remove(Component comp) {
		throw new UnsupportedOperationException("External call to remove(Component) not allowed");
	}

	@Override
	public void addIndexScrollListener(IndexScrollListener listener) {
		indexPanel.addIndexScrollListener(listener);
	}

	@Override
	public int getHeight(BigInteger index) {
		return indexPanel.getHeight(index);
	}

	@Override
	public BigInteger getIndexAfter(BigInteger index) {
		return indexPanel.getIndexAfter(index);
	}

	@Override
	public BigInteger getIndexBefore(BigInteger index) {
		return indexPanel.getIndexBefore(index);
	}

	@Override
	public BigInteger getIndexCount() {
		return indexPanel.getIndexCount();
	}

	@Override
	public boolean isUniformIndex() {
		return true;
	}

	@Override
	public void removeIndexScrollListener(IndexScrollListener listener) {
		indexPanel.removeIndexScrollListener(listener);
	}

	@Override
	public void scrollLineDown() {
		indexPanel.scrollLineDown();
	}

	@Override
	public void scrollLineUp() {
		indexPanel.scrollLineUp();
	}

	@Override
	public void scrollPageDown() {
		indexPanel.scrollPageDown();
	}

	@Override
	public void scrollPageUp() {
		indexPanel.scrollPageUp();
	}

	@Override
	public void showIndex(BigInteger index, int verticalOffset) {
		indexPanel.showIndex(index, verticalOffset);
	}

	@Override
	public void indexModelChanged() {
		// handled by indexPanel
	}

	@Override
	public void indexModelDataChanged(BigInteger start, BigInteger end) {
		// handled by indexPanel
	}

	@Override
	public void indexRangeChanged(BigInteger startIndex, BigInteger endIndex, int yStart,
			int yEnd) {
		if (processingIndexRangeChanged) {
			return;
		}
		processingIndexRangeChanged = true;
		try {
			// need to update all views
			for (FieldPanel fieldPanel : allPanels) {
				fieldPanel.showIndex(startIndex, yStart);
			}
		}
		finally {
			processingIndexRangeChanged = false;
		}
	}
}
