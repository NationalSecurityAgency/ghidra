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
import javax.swing.border.BevelBorder;

import docking.widgets.EventTrigger;
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
import ghidra.util.*;
import ghidra.util.datastruct.ListenerSet;
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

	private boolean highlightCurrentLine;

	private int highlightButton;
	private ListenerSet<LayoutModelListener> layoutListeners =
		new ListenerSet<>(LayoutModelListener.class, false);
	private boolean addingView; // don't respond to cursor location changes while this flag is true
	private final ByteViewerComponentProvider provider;

	private List<AddressSetDisplayListener> displayListeners = new ArrayList<>();
	private ByteViewerIndexedView indexedView;
	private boolean editMode;

	protected ByteViewerPanel(ByteViewerComponentProvider provider) {
		this.provider = provider;
		bytesPerLine = provider.getConfigOptions().getBytesPerLine();
		viewList = new ArrayList<>();
		indexMap = new IndexMap();
		create();
	}

	@Override
	public Dimension getPreferredSize() {

		int rowCount = 20;
		int rowsHeight = rowCount * fontHeight;
		int defaultHeight = rowsHeight + statusPanel.getHeight();

		if (viewList.isEmpty()) {
			// add 20 for border layout vertical gap
			int width = statusPanel.getPreferredSize().width + 20;
			return new Dimension(width, defaultHeight);
		}

		int width = indexPanel.getPreferredSize().width;
		int height = defaultHeight;
		for (ByteViewerComponent c : viewList) {
			Dimension d = c.getPreferredSize();
			width += d.width + 2; // +2 for separator
			height = Math.max(d.height, defaultHeight);
		}

		return new Dimension(width, height);
	}

	void updateColors() {
		for (ByteViewerComponent comp : viewList) {
			comp.updateColors();
		}
	}

	int getHighlightButton() {
		return highlightButton;
	}

	void setHighlightCurrentLineEnabled(boolean b) {
		highlightCurrentLine = b;
		repaint();
	}

	boolean isHighlightCurrentLine() {
		return highlightCurrentLine;
	}

	void setHighlightButton(int highlightButton) {
		this.highlightButton = highlightButton;
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
				offsetField.setText(Integer.toString(blockOffset));

				clearSelection();
			}
		}
		if (indexMap == null) {
			indexMap = new IndexMap();
			startField.setText("00000000");
			endField.setText("00000000");
			offsetField.setText("00000000");
			insertionField.setText("00000000");
		}
		indexFactory.setIndexMap(indexMap);
		indexFactory.setSize(getIndexSizeInChars());

		// Do the following loop twice - once with update off and then with update on.
		// need to do this because all the byte view components must have their models 
		// updated before any one of them tells their dependents about the change.
		for (ByteViewerComponent c : viewList) {
			c.enableIndexUpdate(false);
			c.setIndexMap(indexMap);
		}
		for (ByteViewerComponent c : viewList) {
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
		for (ByteViewerComponent c : viewList) {
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
		for (ByteViewerComponent c : viewList) {
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
		for (ByteViewerComponent c : viewList) {
			modelIndex = c.setViewerCursorLocation(block, index, column);
		}
		if (modelIndex >= 0) {
			insertionField.setText(block.getLocationRepresentation(index));
		}
		updateIndexColumnCurrentLine();
	}

	void updateIndexColumnCurrentLine() {
		// this needs to be called by each ByteViewerComponent when the line index for their
		// cursor changes so that the address column can be updated
		indexPanel.repaint();
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

	public ByteViewerComponent getComponentByName(String name) {
		for (ByteViewerComponent bvc : viewList) {
			if (name.equals(bvc.getDataModel().getName())) {
				return bvc;
			}
		}
		return null;
	}

	protected ByteViewerComponent newByteViewerComponent(DataFormatModel model) {
		return new ByteViewerComponent(this, new ByteViewerLayoutModel(), model, bytesPerLine);
	}

	/**
	 * Add a view to the panel.
	 * 
	 * @param viewName name of the format, e.g., Hex, Ascii, etc.
	 * @param model model that understands the format
	 * @param updateViewPosition true if the view position should be set
	 * @return the new component
	 */
	ByteViewerComponent addView(String viewName, DataFormatModel model,
			boolean updateViewPosition) {

		if (viewList.size() != 0) {
			addingView = true;
		}

		ViewerPosition vp = getViewerPosition();

		ByteViewerComponent c = newByteViewerComponent(model);
		c.setIndexMap(indexMap);
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
				Swing.runLater(() -> indexPanel.setViewerPosition(vp.getIndex(), vp.getXOffset(),
					vp.getYOffset()));
			}
			addingView = false;
		}
		c.updateColors();
		validate();
		repaint();
		return c;
	}

	void removeView(ByteViewerComponent comp) {

		viewList.remove(comp);
		indexedView.removeView(comp);

		if (currentView == comp) {
			currentView = !viewList.isEmpty() ? viewList.get(0) : null;
		}

		comp.dispose();
		validate();
		repaint();
	}

	void setCurrentView(ByteViewerComponent c) {
		currentView = c;
		updateColors();
	}

	void setEditMode(boolean editMode) {
		this.editMode = editMode;
		updateColors();
	}

	boolean getEditMode() {
		return editMode;
	}

	/**
	 * Force the current view to be refreshed.
	 */
	void refreshView() {
		for (ByteViewerComponent c : viewList) {
			c.refreshView();
		}
	}

	void updateLayoutConfigOptions(ByteViewerConfigOptions options) {
		boolean bplChanged = bytesPerLine != options.getBytesPerLine();
		boolean offsetChanged = blockOffset != options.getOffset();
		if (bplChanged || offsetChanged) {
			bytesPerLine = options.getBytesPerLine();
			blockOffset = options.getOffset();

			updateIndexMap();
			offsetField.setText(Integer.toString(blockOffset));
		}
		if (bplChanged) {
			// reset view column widths to preferred width for new bytesPerline
			resetColumnsToDefaultWidths();
		}
	}

	void resetColumnsToDefaultWidths() {
		indexedView.resetViewWidthToDefaults();

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
		for (ByteViewerComponent c : viewList) {
			if (source == c) {
				continue;
			}
			c.setViewerCursorLocation(block, offset, column);
		}
		updateIndexColumnCurrentLine();
	}

	void setCurrentNonMappedIndex(BigInteger index, ByteViewerComponent source) {
		// used to update all viewer columns to a line index that isn't mapped to a byte offset
		for (ByteViewerComponent c : viewList) {
			if (c != source) {
				c.setCursorPosition(index, 0, 0, 0, EventTrigger.INTERNAL_ONLY);
			}
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

		for (ByteViewerComponent c : viewList) {
			if (source == c) {
				continue;
			}
			c.setViewerSelection(selection);
		}
	}

	void updateLiveSelection(ByteViewerComponent bvc, ByteBlockSelection selection) {

		provider.updateLiveSelection(bvc, selection);

		for (ByteViewerComponent c : viewList) {
			if (c == bvc) {
				continue;
			}
			c.setViewerSelection(selection);
		}

		updateIndexColumnCurrentLine();
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

		for (ByteViewerComponent c : viewList) {
			c.returnToView(block, offset, vpos);
		}
		indexPanel.setViewerPosition(vpos.getIndex(), vpos.getXOffset(), vpos.getYOffset());
	}

	void restoreConfigState(ByteViewerConfigOptions options) {
		updateLayoutConfigOptions(options);
	}

	void programWasRestored() {
		updateIndexMap();
		refreshView();
	}

	protected int getBytesPerLine() {
		return bytesPerLine;
	}

	void dispose() {
		for (ByteViewerComponent comp : viewList) {
			comp.dispose();
		}
		viewList.clear();
		indexMap = new IndexMap();
		blockSet = null;
		layoutListeners.clear();
	}

	/**
	 * Create the components for this top level panel.
	 */
	private void create() {

		setLayout(new BorderLayout(10, 0));
		setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));

		setFont(ByteViewerComponentProvider.DEFAULT_FONT); // side-effect sets fontMetrics

		// for the index/address column
		indexFactory = new IndexFieldFactory(fontMetrics);
		indexPanel = new FieldPanel(this, "Byte Viewer");

		indexPanel.enableSelection(false);
		indexPanel.setCursorOn(false);
		indexPanel.setFocusable(false);
		indexPanel.addLayoutListener(this);
		indexPanel.setBackgroundColor(ByteViewerComponentProvider.BG_COLOR);
		indexPanel.setBackgroundColorModel(new ByteViewerBGColorModel(this));

		indexedView = new ByteViewerIndexedView(indexPanel);
		IndexedScrollPane indexedScrollPane = new IndexedScrollPane(indexedView);
		indexedScrollPane.setWheelScrollingEnabled(false);
		indexedScrollPane.setColumnHeaderComp(indexedView.getColumnHeader());
		indexedScrollPane.setBackground(ByteViewerComponentProvider.BG_COLOR);

		statusPanel = createStatusPanel();
		add(indexedScrollPane, BorderLayout.CENTER);
		add(statusPanel, BorderLayout.SOUTH);

		Gui.registerFont(this, ByteViewerComponentProvider.DEFAULT_FONT_ID);

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
		for (ByteViewerComponent c : viewList) {
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
		for (ByteViewerComponent c : viewList) {
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
		// creates the field layout for the specified index line in the Address column
		BigInteger numIndexes = getNumIndexes();
		if (numIndexes.compareTo(BigInteger.ZERO) > 0 && index.compareTo(numIndexes) >= 0) {
			return null;
		}

		Field field = indexFactory.getField(index);
		if (field == null) {
			int height = fontMetrics.getMaxAscent() + fontMetrics.getMaxDescent();
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
		layoutListeners.invoke().modelSizeChanged(IndexMapper.IDENTITY_MAPPER);
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
		if (component == null || blockSet == null || layouts.isEmpty()) {
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

	private void updateFontDependantInfo() {
		fontMetrics = getFontMetrics(getFont());
		fontHeight = fontMetrics.getHeight();
		if (indexFactory != null) {
			indexFactory.setFontMetrics(fontMetrics);
		}
	}

	@Override
	public void setFont(Font font) {
		super.setFont(font);
		updateFontDependantInfo();
	}

}
