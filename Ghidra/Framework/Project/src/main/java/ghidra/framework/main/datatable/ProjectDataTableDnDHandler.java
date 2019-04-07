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
package ghidra.framework.main.datatable;

import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.dnd.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.CellRendererPane;
import javax.swing.table.*;

import docking.widgets.table.GTable;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.framework.main.datatree.DataTreeDragNDropHandler;
import ghidra.framework.model.DomainFile;

public class ProjectDataTableDnDHandler implements DragSourceListener, DragGestureListener {

	private static final DataFlavor DOMAIN_FILE_LIST_FLAVOR =
		DataTreeDragNDropHandler.localDomainFileFlavor;
	static final DataFlavor[] ROW_DATA_FLAVORS = { DOMAIN_FILE_LIST_FLAVOR };
	public static List<DomainFileInfo> selectedData;

	private GTable table;
	private ProjectDataTableModel model;

	ProjectDataTableDnDHandler(GTable table, ProjectDataTableModel model) {
		this.table = table;
		this.model = model;

		performMultiSelectionMouseFix();

		DragSource dragSource = DragSource.getDefaultDragSource();
		dragSource.createDefaultDragGestureRecognizer(table, DnDConstants.ACTION_COPY_OR_MOVE,
			this);
	}

	private void performMultiSelectionMouseFix() {

		//
		// Insert our listener into the front of the listeners so that we get a chance to
		// handle events first.
		//

		MouseListener[] oldMouseListeners = table.getMouseListeners();
		MouseMotionListener[] oldMouseMotionListeners = table.getMouseMotionListeners();
		for (MouseListener l : oldMouseListeners) {
			table.removeMouseListener(l);
		}
		for (MouseMotionListener l : oldMouseMotionListeners) {
			table.removeMouseMotionListener(l);
		}

		DnDMouseListener newListener = new DnDMouseListener();
		table.addMouseListener(newListener);
		table.addMouseMotionListener(newListener);

		for (MouseListener l : oldMouseListeners) {
			table.addMouseListener(l);
		}
		for (MouseMotionListener l : oldMouseMotionListeners) {
			table.addMouseMotionListener(l);
		}
	}

//======================================================
// DragSourceListener method
//======================================================
	@Override
	public void dragDropEnd(DragSourceDropEvent dsde) {
//		renderer.setDropRow(-1);
//		oldRow = -1;
		table.repaint();
//		provider.setIgnoreSelectionChange(false);
	}

	@Override
	public void dragEnter(DragSourceDragEvent dsde) {
		// don't care
	}

	@Override
	public void dragExit(DragSourceEvent dse) {
		setCursor(DnDConstants.ACTION_NONE, dse.getDragSourceContext());
	}

	private void setCursor(int action, DragSourceContext dragSourceContext) {
		Cursor cursor = DragSource.DefaultCopyNoDrop;
		switch (action) {
			case DnDConstants.ACTION_COPY:
				cursor = DragSource.DefaultCopyDrop;
				break;
			case DnDConstants.ACTION_MOVE:
				cursor = DragSource.DefaultMoveDrop;
				break;
			case DnDConstants.ACTION_LINK:
				cursor = DragSource.DefaultLinkDrop;
		}
		dragSourceContext.setCursor(cursor);
	}

	@Override
	public void dragOver(DragSourceDragEvent dsde) {
		setCursor(dsde.getDropAction(), dsde.getDragSourceContext());
	}

	@Override
	public void dropActionChanged(DragSourceDragEvent dsde) {
		// don't care
	}

//======================================================
// DragGestureListener method
//======================================================
	@Override
	public void dragGestureRecognized(DragGestureEvent dragEvent) {

		// check input event: if any button other than MB1 is pressed,
		// don't attempt to process the drag and drop event.
		InputEvent ie = dragEvent.getTriggerEvent();
		int modifiers = ie.getModifiersEx();
		if ((modifiers & InputEvent.BUTTON2_DOWN_MASK) != 0 ||
			(modifiers & InputEvent.BUTTON3_DOWN_MASK) != 0) {
			return;
		}

		selectedData = createSelectionList(table);

		Transferable transferable = new DomainFileTransferable(selectedData);
		Image image = getDragImage(selectedData);

		try {

			dragEvent.startDrag(DragSource.DefaultMoveDrop, image, new Point(0, 0), transferable,
				this);
		}
		catch (InvalidDnDOperationException exc) {
			// not sure why, but apparently we don't care
		}
	}

	private Image getDragImage(List<DomainFileInfo> files) {
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() != OperatingSystem.MAC_OS_X) {
			return null;
		}

		Container parent = table.getParent();
		Dimension size = parent.getSize(); // assuming this is JViewport
		BufferedImage bufferedImage =
			new BufferedImage(size.width, size.height, BufferedImage.TYPE_INT_ARGB);

		Graphics graphics = bufferedImage.getGraphics();
		graphics.setClip(0, 0, size.width, size.height);

		paintRecords(files, graphics);

		// now we will create a fade effect using an alpha composite and a gradient
		Graphics2D g2 = (Graphics2D) graphics;
		GradientPaint mask;
		Color treeBackground = table.getBackground();
		Color transparentTreeBackground = new Color(treeBackground.getRed(),
			treeBackground.getGreen(), treeBackground.getBlue(), 200);
		mask = new GradientPaint(0, 0, transparentTreeBackground, 0, size.height >> 1,
			new Color(1.0f, 1.0f, 1.0f, 0.0f));
		g2.setPaint(mask);

		// Sets the alpha composite
		g2.setComposite(AlphaComposite.DstIn);

		// Paints the mask
		g2.fillRect(0, 0, size.width, size.height);

		return bufferedImage;
	}

	/** Paint each of the given records that is inside of the clips */
	private void paintRecords(List<DomainFileInfo> records, Graphics g) {
		CellRendererPane rendererPane = new CellRendererPane();
		paintCells(records, rendererPane, g);
	}

	private void paintCells(List<DomainFileInfo> domainFileInfos, CellRendererPane rendererPane,
			Graphics g) {
		TableColumnModel cm = table.getColumnModel();
		int columnMargin = cm.getColumnMargin();

		Rectangle clip = g.getClipBounds();
		int yOffset = clip.y;

		int rowCount = domainFileInfos.size();
		int columnCount = table.getColumnCount();

		int modelRow = model.getRowIndex(domainFileInfos.get(0));
		Rectangle cellRect = table.getCellRect(modelRow, 0, false);
		int startYOffset = cellRect.y;

		TableColumn aColumn;
		int columnWidth;
		for (int row = 0; row < rowCount; row++) {
			if (clip.y + clip.height < yOffset - startYOffset) {
				return; // no need to paint past the end of our visible area
			}

			modelRow = model.getRowIndex(domainFileInfos.get(row));
			cellRect = table.getCellRect(modelRow, 0, false);
			cellRect.y -= startYOffset; // paint the row at the top of the graphics, not where it really lives
			yOffset += cellRect.height;
			for (int column = 0; column < columnCount; column++) {
				aColumn = cm.getColumn(column);
				columnWidth = aColumn.getWidth();
				cellRect.width = columnWidth - columnMargin;
				paintCell(rendererPane, g, cellRect, modelRow, column);
				cellRect.x += columnWidth;
			}
		}
	}

	private void paintCell(CellRendererPane rendererPane, Graphics g, Rectangle cellRect, int row,
			int column) {
		TableCellRenderer tableRenderer = table.getCellRenderer(row, column);
		Component component = table.prepareRenderer(tableRenderer, row, column);
		rendererPane.paintComponent(g, component, table, cellRect.x, cellRect.y, cellRect.width,
			cellRect.height, true);
	}

	private List<DomainFileInfo> createSelectionList(GTable tableToSelect) {
		ArrayList<DomainFileInfo> list = new ArrayList<DomainFileInfo>();

		int[] rows = table.getSelectedRows();

		if (rows == null) {
			return list;
		}
		for (int row : rows) {
			list.add(model.getRowObject(row));
		}
		return list;
	}

	class DomainFileTransferable implements Transferable {
		private List<DomainFileInfo> list;

		DomainFileTransferable(List<DomainFileInfo> list) {
			this.list = list;
		}

		@Override
		public Object getTransferData(DataFlavor flavor)
				throws UnsupportedFlavorException, IOException {
			if (DOMAIN_FILE_LIST_FLAVOR.equals(flavor)) {
				return getDomainFileList();
			}
			throw new UnsupportedFlavorException(flavor);
		}

		private Object getDomainFileList() {
			List<DomainFile> domainFileList = new ArrayList<DomainFile>();
			for (DomainFileInfo domainFileInfo : list) {
				domainFileList.add(domainFileInfo.getDomainFile());
			}
			return domainFileList;
		}

		@Override
		public DataFlavor[] getTransferDataFlavors() {
			return ROW_DATA_FLAVORS;
		}

		@Override
		public boolean isDataFlavorSupported(DataFlavor flavor) {
			return DOMAIN_FILE_LIST_FLAVOR.equals(flavor);
		}
	}

	private class DnDMouseListener extends MouseAdapter {

		private boolean consuming = false;

		@Override
		public void mousePressed(MouseEvent e) {
			consuming = maybeConsumeEvent(e);
		}

		@Override
		public void mouseReleased(MouseEvent e) {
			if (!consuming) {
				return;
			}

			// continue to consume the event that was started during the pressed event, for symmetry
			maybeConsumeEvent(e);
			consuming = false;
		}

		@Override
		public void mouseDragged(MouseEvent e) {
			// always consume the drag so that Java does not change the selection
			e.consume();
		}

		private boolean maybeConsumeEvent(MouseEvent e) {

			if (!isBasicLeftClick(e)) {
				return false;
			}

			// don't let other listeners process the event if we are 'pressing' the mouse 
			// button on an already selected row (to prevent de-selecting a multi-selection for
			// a drag operation)
			int row = table.rowAtPoint(e.getPoint());
			if (table.isRowSelected(row)) {
				e.consume();
				return true;
			}

			return false;
		}

		private boolean isBasicLeftClick(MouseEvent e) {

			if (e.getButton() != MouseEvent.BUTTON1) {
				return false;
			}

			if (e.getClickCount() > 1) {
				return false;
			}

			if (e.isControlDown() || e.isAltDown() || e.isShiftDown() || e.isMetaDown()) {
				return false;
			}

			return true;
		}
	}

}
