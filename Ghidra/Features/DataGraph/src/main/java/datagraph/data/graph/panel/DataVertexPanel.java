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
package datagraph.data.graph.panel;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.*;

import datagraph.data.graph.*;
import datagraph.data.graph.panel.model.column.CompactDataColumnModel;
import datagraph.data.graph.panel.model.column.ExpandedDataColumnModel;
import datagraph.data.graph.panel.model.row.DataRowObject;
import datagraph.data.graph.panel.model.row.DataTrableRowModel;
import datagraph.graph.explore.EgVertex;
import docking.GenericHeader;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.widgets.trable.GTrable;
import docking.widgets.trable.GTrableColumnModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.util.datastruct.Range;
import resources.Icons;

/**
 * Main component to be displayed in a data {@link DegVertex}. It consists of a generic header and
 * a scrollable GTrable that displays the elements of a {@link Data} item. 
 */
public class DataVertexPanel extends JPanel {
	private GenericHeader genericHeader;
	private GTrable<DataRowObject> gTrable;
	private DataTrableRowModel model;
	private JScrollPane scroll;
	private int headerHeight;
	private Comparator<int[]> pathComparator = new DtComponentPathComparator();

	private Dimension userSize;

	private Rectangle preferredShape = new Rectangle(0, 0, 0, 0);
	private DataDegVertex vertex;
	private DegController controller;

	private Map<EgVertex, IncomingEdgeOffsetInfo> incomingEdgeOffsetMap = new HashMap<>();
	private Map<EgVertex, OutgoingEdgeOffsetInfo> outgoingEdgeOffsetMap = new HashMap<>();
	private boolean cachedOutgoingOffsetsValid;
	private boolean cachedIncomingOffsetsValid;
	private GTrableColumnModel<DataRowObject> dataColumnModel;

	/**
	 * Constructor
	 * @param controller the data exploration graph controller
	 * @param vertex the vertex that created this DataVertexPanel
	 * @param compactFormat true if a compact format should be used to display the data
	 */
	public DataVertexPanel(DegController controller, DataDegVertex vertex, boolean compactFormat) {
		super(new BorderLayout());
		this.controller = controller;
		this.vertex = vertex;
		buildComponent(vertex.getData(), compactFormat);
		addKeyListener(new DataVertexKeyListener());
		updateTitle();
		headerHeight = genericHeader.getPreferredSize().height;
		scroll.getViewport().addChangeListener(e -> invalidateCaches());

	}

	/**
	 * Sets if the display should be compact or expanded.
	 * @param b if true, use compact format
	 */
	public void setCompactFormat(boolean b) {
		if (!isExpandable()) {
			return;
		}
		dataColumnModel = b ? new CompactDataColumnModel() : new ExpandedDataColumnModel();
		gTrable.setColumnModel(dataColumnModel);
		userSize = null;
		updateShape();
	}

	/**
	 * Associates an outgoing vertex with the component path of the internal data element
	 * within this vertex that connects to that external vertex. This is used to draw the
	 * outgoing edge at the same y offset where the referring data is displayed in the scrollable
	 * display area.
	 * @param end the external vertex we are associating with a component path
	 * @param componentPath the component path of the data whose reference generated the external
	 * vertex.
	 */
	public void addOutgoingEdge(EgVertex end, int[] componentPath) {
		cleanUpDeletedEdges();
		outgoingEdgeOffsetMap.put(end, new OutgoingEdgeOffsetInfo(componentPath));
		cachedOutgoingOffsetsValid = false;
	}

	@Override
	public String getToolTipText(MouseEvent event) {
		Component source = event.getComponent();
		if (SwingUtilities.isDescendingFrom(source, genericHeader)) {
			if (!(source instanceof JComponent)) {
				return null;
			}
			JComponent jComponent = (JComponent) source;
			return jComponent.getToolTipText();
		}
		return null;
	}

	/**
	 * Associates an incoming vertex with the Address of the internal data element
	 * within this vertex that the external vertex refers to. This is used to draw the
	 * incoming edge at the same y offset where the referred to data is displayed in the scrollable
	 * display area. We only record this information for references that are not to the vertex's
	 * base address. References  to the base address are always drawn to point at top left corner, 
	 * but references directly to sub-data elements are drawn to point to the sub-element so we
	 * need to track where those y-offsets are located for those sub-data elements.
	 * 
	 * @param start the external vertex we are associating with an offcut address in the vertex
	 * @param address the offcut address that the external vertex refers to
	 */
	public void addIncommingEdge(EgVertex start, Address address) {
		cleanUpDeletedEdges();
		// only need to track the offcut incoming edges
		if (!address.equals(vertex.getAddress())) {
			incomingEdgeOffsetMap.put(start, new IncomingEdgeOffsetInfo(address));
			cachedIncomingOffsetsValid = false;
		}
	}

	/**
	 * {@return the y offset from center of where to draw the incoming edge endpoint.}
	 * @param v the external vertex for an incoming edge
	 */
	public int getIncommingEdgeOffsetFromCenter(EgVertex v) {
		if (!cachedIncomingOffsetsValid) {
			computeIncomingEdgeOffset();
		}
		IncomingEdgeOffsetInfo info = incomingEdgeOffsetMap.get(v);
		if (info == null) {
			// if not in map, then this edge is not offset, so return the top of the vertex
			return -getSize().height / 2 + headerHeight / 2;
		}
		int yOffsetFromTop = info.yOffset;
		return yOffsetFromTop - getSize().height / 2;
	}

	/**
	 * {@return the y offset from center of where to draw the outgoing edge startpoint.}
	 * @param v the external vertex for an outgoing edge
	 */
	public int getOutgoingEdgeOffsetFromCenter(EgVertex v) {
		if (!cachedOutgoingOffsetsValid) {
			computeOutgoingEdgeOffsets();
		}
		OutgoingEdgeOffsetInfo linkInfo = outgoingEdgeOffsetMap.get(v);
		int yOffsetFromTop = (linkInfo != null ? linkInfo.yOffset : 0);
		return yOffsetFromTop - getSize().height / 2;
	}

	/**
	 * Adds an action to this vertex's header component.
	 * @param action the action to add
	 */
	public void addAction(DockingAction action) {
		genericHeader.actionAdded(action);
		genericHeader.update();
		headerHeight = genericHeader.getPreferredSize().height;
	}

	/**
	 * Sets the size of this panel
	 * @param size the new size for this panel
	 */
	public void setSizeByUser(Dimension size) {
		userSize = size;
		updateShape();
		controller.repaint();
	}

	/**
	 * {@return the shape of this panel.}
	 */
	public Shape getShape() {
		return preferredShape;
	}

	/**
	 * Updates the cached shape of this panel
	 * @return true if the shape changed
	 */
	public boolean updateShape() {
		gTrable.invalidate();
		Dimension preferredSize = scroll.getPreferredSize();
		int width = userSize != null ? userSize.width : preferredSize.width;
		int height = userSize != null ? userSize.height : preferredSize.height + headerHeight;
		if (!isOpen()) {
			height = preferredSize.height + headerHeight;
		}
		if (preferredShape.width == width && preferredShape.height == height) {
			return false;
		}
		preferredShape.width = width;
		preferredShape.height = height;

		return true;
	}

	/**
	 * Sets this vertex to be selected or not.
	 * @param selected if true the vertex is selected
	 */
	public void setSelected(boolean selected) {
		genericHeader.setSelected(selected);
		if (selected) {
			navigate(gTrable.getSelectedRow());
		}
	}

	/**
	 * Sets this vertex to be focused or not.
	 * @param focused if true the vertex is focused
	 */
	public void setFocused(boolean focused) {
		if (focused) {
			navigate(gTrable.getSelectedRow());
		}
	}

	/**
	 * Dispose this component;
	 */
	public void dispose() {
		vertex = null;
	}

	/**
	 * {@return the amount the current scroll if offset from an even row boundary.}
	 */
	public int getScrollRowOffset() {
		return gTrable.getRowOffcut();
	}

	/**
	 * Adds new vertices for all outgoing references from the given row.
	 * @param row the row containing the data object to get references and add outgoing vertices.
	 */
	public void openPointerReference(int row) {
		DataRowObject dataDisplayRow = model.getRow(row);
		if (dataDisplayRow.hasOutgoingReferences()) {
			Data data = dataDisplayRow.getData();
			controller.addOutGoingReferences(vertex, data);
		}
	}

	/**
	 * {@return the height of the vertex header component.}
	 */
	public int getHeaderHeight() {
		return headerHeight;
	}

	/**
	 * Compares the the associated data component paths for the given external outgoing vertices.
	 * The vertices are ordered by the associated data paths for the given vertices.
	 * @param v1 vertex 1
	 * @param v2 vertex 2
	 * @return a negative integer, zero, or a positive integer as the
	 *         first argument is less than, equal to, or greater than the
	 *         second.
	 */
	public int comparePaths(DegVertex v1, DegVertex v2) {
		// use the edge info to get the component paths since it is cheaper than getting
		// it from the data objects which computes the path every time you ask it.
		OutgoingEdgeOffsetInfo edgeInfo1 = outgoingEdgeOffsetMap.get(v1);
		OutgoingEdgeOffsetInfo edgeInfo2 = outgoingEdgeOffsetMap.get(v2);
		return pathComparator.compare(edgeInfo1.componentPath, edgeInfo2.componentPath);
	}

	/**
	 * Sets this vertex to be the overall graph original source vertex or not. Only one vertex
	 * in the graph should be set to true.
	 * @param b if true, this vertex will be set as the original source vertex (shows a icon
	 * in the header if it is the original source vertex.)
	 */
	public void setIsRoot(boolean b) {
		if (b) {
			genericHeader.setIcon(Icons.HOME_ICON);
		}
		else {
			genericHeader.setIcon(null);
		}
	}

	/**
	 * Causes the header to relayout it components. Usually called after actions are added or 
	 * removed.
	 */
	public void updateHeader() {
		genericHeader.update();
	}

	/**
	 * Expands the given row and its child rows recursively.
	 * @param rowIndex the index to expand. A value of 0 will expand all possible rows.
	 */
	public void expandRecursivley(int rowIndex) {
		gTrable.expandRowRecursively(rowIndex);
	}

	/**
	 * Fully expands all expandable rows.
	 */
	public void expandAll() {
		gTrable.expandAll();
	}

	/**
	 * Collapses all rows.
	 */
	public void collapseAll() {
		gTrable.collapseAll();
	}

	/**
	 * {@return  true if the data being display is expandable.}
	 */
	public boolean isExpandable() {
		return model.getRow(0).isExpandable();
	}

	/**
	 * Expands the given row.
	 * @param row the row to expand
	 */
	public void expand(int row) {
		model.expandRow(row);
	}

	/**
	 * Sets a new {@link Data} object for this panel.
	 * @param newData the new Data object to display in this panel
	 */
	public void setData(Data newData) {
		boolean isFirstLevelOpen = model.isExpanded(0);
		model.setData(newData);
		if (isFirstLevelOpen) {
			model.expandRow(0);
		}
	}

	/**
	 * {@return the title of this vertex.}
	 */
	public String getTitle() {
		return genericHeader.getTitle();
	}

	/**
	 * {@return a list of all the DataRowObjects in this component.}
	 */
	public List<DataRowObject> getRowObjects() {
		List<DataRowObject> list = new ArrayList<>();
		int n = model.getRowCount();
		for (int i = 0; i < n; i++) {
			DataRowObject row = model.getRow(i);
			list.add(row);
		}
		return list;
	}

	/**
	 * {@return the action with the given name or null if the header has not action with that name.}
	 * @param name the name of the action to find
	 */
	public DockingActionIf getAction(String name) {
		return genericHeader.getAction(name);
	}

	private void cleanUpDeletedEdges() {
		Set<DegVertex> outgoingVertices = controller.getOutgoingVertices(vertex);
		outgoingEdgeOffsetMap.keySet().retainAll(outgoingVertices);

		Set<DegVertex> incomingVertices = controller.getIncomingVertices(vertex);
		incomingEdgeOffsetMap.keySet().retainAll(incomingVertices);

	}

	private void invalidateCaches() {
		cachedIncomingOffsetsValid = false;
		cachedOutgoingOffsetsValid = false;
	}

	private void buildComponent(Data data, boolean compact) {
		model = new DataTrableRowModel(data);
		if (!isExpandable()) {
			// if we only ever have a top level row, then no point in being in expanded format
			compact = true;
		}
		dataColumnModel = compact ? new CompactDataColumnModel() : new ExpandedDataColumnModel();
		model.expandRow(0);
		gTrable = new GTrable<>(model, dataColumnModel);
		gTrable.setPreferredVisibleRowCount(1, 15);
		gTrable.addCellClickedListener(this::cellClicked);
		model.addListener(this::modelDataChanged);
		gTrable.addSelectedRowConsumer(this::selectedRowChanged);

		scroll = new JScrollPane(gTrable);
		scroll.getViewport().addChangeListener(e -> controller.repaint());
		add(scroll, BorderLayout.CENTER);

		genericHeader = new GenericHeader();
		genericHeader.setComponent(scroll);
		add(genericHeader, BorderLayout.NORTH);

	}

	private void modelDataChanged() {
		if (updateShape()) {
			controller.relayoutGraph();
		}
		cachedOutgoingOffsetsValid = false;
		cachedIncomingOffsetsValid = false;
		controller.repaint();
	}

	private void computeIncomingEdgeOffset() {
		cachedIncomingOffsetsValid = true;
		if (incomingEdgeOffsetMap.isEmpty()) {
			return;
		}
		int rowHeight = gTrable.getRowHeight();
		int rowOffset = gTrable.getRowOffcut();
		Dimension size = getSize();

		List<Address> visibleAddresses = getVisibleAddresses();
		Address minAddress = visibleAddresses.get(0);
		Address maxAddress = visibleAddresses.get(visibleAddresses.size() - 1);
		for (IncomingEdgeOffsetInfo info : incomingEdgeOffsetMap.values()) {
			Address address = info.address;
			if (address.compareTo(minAddress) < 0) {
				info.yOffset = headerHeight;
				continue;
			}
			if (address.compareTo(maxAddress) > 0) {
				info.yOffset = size.height;
				continue;
			}
			int index = getIndex(visibleAddresses, address);
			int offset = index * rowHeight - rowOffset + rowHeight / 2 + headerHeight;
			if (size.height > headerHeight) {
				offset = Math.clamp(offset, headerHeight, size.height);
			}
			info.yOffset = offset;
		}

	}

	private void computeOutgoingEdgeOffsets() {
		cachedOutgoingOffsetsValid = true;
		int rowHeight = gTrable.getRowHeight();
		int rowOffset = gTrable.getRowOffcut();
		Dimension size = getSize();

		List<int[]> paths = getVisibleDataPaths();
		int[] minPath = paths.get(0);
		for (OutgoingEdgeOffsetInfo info : outgoingEdgeOffsetMap.values()) {
			int[] path = info.componentPath;
			if (pathComparator.compare(path, minPath) < 0) {
				info.yOffset = headerHeight;
				continue;
			}
			int index = getIndex(paths, path);
			int offset = index * rowHeight - rowOffset + rowHeight / 2 + headerHeight;
			if (size.height > headerHeight) {
				offset = Math.clamp(offset, headerHeight, size.height);
			}
			info.yOffset = offset;
		}
	}

	private int getIndex(List<int[]> paths, int[] componentPath) {
		int index = Collections.binarySearch(paths, componentPath, pathComparator);

		if (index < 0) {
			index = -index - 2;
		}
		return index;
	}

	private int getIndex(List<Address> addresses, Address address) {
		int index = Collections.binarySearch(addresses, address);

		// We have already checked that the path is > the first row displayed and less than
		// the last row we displayed. Therefore, it the binary search doesn't find a direct hit,
		// it means the desired row is currently in a parent that is not expanded, so we want
		// the offset to be the parent. Normally, the convention for binary search is to do
		// -index-1 to get the location where the value would be inserted. But we want the parent,
		// which is back one more, so we subtract 2 instead of 1.

		if (index < 0) {
			index = -index - 2;
		}

		// get the bottom most address (lowest level component) if more than one row have
		// the same address
		while (index < addresses.size() - 1) {
			if (!addresses.get(index + 1).equals(address)) {
				break;
			}
			index++;
		}
		return index;
	}

	private void updateTitle() {
		Data data = model.getData();
		String title = "@ " + data.getAddressString(false, false);
		String label = data.getLabel();
		if (label != null) {
			title = label + " " + title;
		}
		genericHeader.setTitle(title);
	}

	private boolean isOpen() {
		return model.getRow(0).isExpanded();
	}

	private class DataVertexKeyListener implements KeyListener {

		@Override
		public void keyTyped(KeyEvent e) {
			KeyboardFocusManager kfm =
				KeyboardFocusManager.getCurrentKeyboardFocusManager();
			kfm.redispatchEvent(gTrable, e);
			e.consume(); // consume all events; signal that our text area will handle them
		}

		@Override
		public void keyReleased(KeyEvent e) {
			KeyboardFocusManager kfm =
				KeyboardFocusManager.getCurrentKeyboardFocusManager();
			kfm.redispatchEvent(gTrable, e);
			e.consume(); // consume all events; signal that our text area will handle them
		}

		@Override
		public void keyPressed(KeyEvent e) {
			KeyboardFocusManager kfm =
				KeyboardFocusManager.getCurrentKeyboardFocusManager();
			kfm.redispatchEvent(gTrable, e);
			e.consume(); // consume all events; signal that our text area will handle them
		}

	}

	private List<Address> getVisibleAddresses() {
		Range visibleRows = gTrable.getVisibleRows();
		List<Address> visiblePaths = new ArrayList<>((int) visibleRows.size());
		for (int i = visibleRows.min; i <= visibleRows.max; i++) {
			DataRowObject displayRow = model.getRow(i);
			Data data = displayRow.getData();
			visiblePaths.add(data.getAddress());
		}
		return visiblePaths;

	}

	private List<int[]> getVisibleDataPaths() {
		Range visibleRows = gTrable.getVisibleRows();
		List<int[]> visiblePaths = new ArrayList<>((int) visibleRows.size());
		for (int i = visibleRows.min; i <= visibleRows.max; i++) {
			DataRowObject displayRow = model.getRow(i);
			Data data = displayRow.getData();
			visiblePaths.add(data.getComponentPath());
		}
		return visiblePaths;
	}

	private void cellClicked(int row, int column, MouseEvent ev) {
		if (isPointerButtonColumn(column)) {
			openPointerReference(row);
		}
	}

	private boolean isPointerButtonColumn(int column) {
		boolean isCompact = dataColumnModel instanceof CompactDataColumnModel;
		int pointerColumn = isCompact ? 2 : 3;
		return column == pointerColumn;
	}

	private void selectedRowChanged(int row) {
		controller.repaint();
		navigate(row);
	}

	private void navigate(int row) {
		if (row < 0) {
			row = 0;	// if now row selected, use the first row to navigate
		}
		DataRowObject dataDisplayRow = model.getRow(row);
		Data data = dataDisplayRow.getData();
		controller.navigateOut(data.getAddress(), data.getComponentPath());

	}

	public boolean isSelectedRowExpandable() {
		int row = gTrable.getSelectedRow();
		if (row < 0) {
			return false;
		}
		return model.isExpandable(row);
	}

	public void expandSelectedRowRecursively() {
		int row = gTrable.getSelectedRow();
		if (row >= 0) {
			gTrable.expandRowRecursively(row);
		}
	}

	private static class OutgoingEdgeOffsetInfo {
		public int[] componentPath;
		public int yOffset;

		OutgoingEdgeOffsetInfo(int[] componentPath) {
			this.componentPath = componentPath;
			yOffset = 0;
		}
	}

	private static class IncomingEdgeOffsetInfo {
		public Address address;
		public int yOffset;

		IncomingEdgeOffsetInfo(Address toAddress) {
			this.address = toAddress;
		}
	}
}
