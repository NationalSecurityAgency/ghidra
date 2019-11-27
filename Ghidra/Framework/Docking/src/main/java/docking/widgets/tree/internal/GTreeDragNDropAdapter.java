/* ###
 * IP: GHIDRA
 * NOTE: Z
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
package docking.widgets.tree.internal;

import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.util.Msg;

import java.awt.*;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.*;
import java.awt.event.InputEvent;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.tree.TreeCellRenderer;
import javax.swing.tree.TreePath;

import docking.widgets.tree.*;
import docking.widgets.tree.support.GTreeDragNDropHandler;
import docking.widgets.tree.support.GTreeNodeTransferable;

public class GTreeDragNDropAdapter implements DragSourceListener, DragGestureListener,
		DropTargetListener {

	private JTree tree;
	private GTreeDragNDropHandler dragNDropHandler;
	private GTree gTree;

	public GTreeDragNDropAdapter(GTree gTree, JTree tree, GTreeDragNDropHandler dragNDropHandler) {
		this.gTree = gTree;
		this.tree = tree;
		this.dragNDropHandler = dragNDropHandler;
		DragSource dragSource = DragSource.getDefaultDragSource();
		dragSource.createDefaultDragGestureRecognizer(tree,
			dragNDropHandler.getSupportedDragActions(), this);

		new DropTarget(tree, dragNDropHandler.getSupportedDragActions(), this, true);
	}

//======================================================
// DragSourceListener method
//======================================================
	@Override
	public void dragDropEnd(DragSourceDropEvent dsde) {
		resetRenderer();
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

		Point p = dragEvent.getDragOrigin();
		TreePath path = tree.getClosestPathForLocation(p.x, p.y);

		if (!tree.isPathSelected(path)) {
			return;
		}
		List<GTreeNode> selectedData = createSelectionList(tree.getSelectionPaths());
		if (!dragNDropHandler.isStartDragOk(selectedData, dragEvent.getDragAction())) {
			return;
		}

		Transferable transferable = new GTreeNodeTransferable(dragNDropHandler, selectedData);

		Image image = getDragImage(selectedData);

		try {
			dragEvent.startDrag(DragSource.DefaultCopyNoDrop, image, new Point(-10, -30),
				transferable, this);
		}
		catch (InvalidDnDOperationException exc) {
			Msg.debug(this, "Unable to initiate drag from tree", exc);
		}
	}

	private Image getDragImage(List<GTreeNode> nodes) {
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() != OperatingSystem.MAC_OS_X) {
			return null;
		}

		Container parent = tree.getParent();
		Dimension size = parent.getSize(); // assuming this is JViewport
		BufferedImage bufferedImage =
			new BufferedImage(size.width, size.height, BufferedImage.TYPE_INT_ARGB);

		Graphics graphics = bufferedImage.getGraphics();
		graphics.setClip(0, 0, size.width, size.height);

		paintNodes(nodes, graphics);

		// now we will create a fade effect using an alpha composite and a gradient
		Graphics2D g2 = (Graphics2D) graphics;
		GradientPaint mask;
		Color treeBackground = tree.getBackground();
		Color transparentTreeBackground =
			new Color(treeBackground.getRed(), treeBackground.getGreen(), treeBackground.getBlue(),
				100);
		mask =
			new GradientPaint(0, 0, transparentTreeBackground, 0, size.height >> 1, new Color(1.0f,
				1.0f, 1.0f, 0.0f));
		g2.setPaint(mask);

		// Sets the alpha composite
		g2.setComposite(AlphaComposite.DstIn);

		// Paints the mask
		g2.fillRect(0, 0, size.width, size.height);

		return bufferedImage;
	}

	/** Paint each of the given nodes that is inside of the clips */
	private void paintNodes(List<GTreeNode> nodes, Graphics g) {
		TreeCellRenderer cellRenderer = tree.getCellRenderer();
		Rectangle clip = g.getClipBounds();
		Container parent = tree.getParent();
		int yOffset = 0;

		try {
			for (GTreeNode node : nodes) {

				int row = tree.getRowForPath(node.getTreePath());
				Rectangle rowBounds = tree.getRowBounds(row);
				rowBounds = SwingUtilities.convertRectangle(tree, rowBounds, parent);
				if (clip.y > rowBounds.y + rowBounds.height) {
					continue; // above our clip
				}

				if (clip.y + clip.height < rowBounds.y + rowBounds.height) {
					// painted past the bounds of our clip
					return;
				}

				Component renderer =
					cellRenderer.getTreeCellRendererComponent(tree, node, true, true,
						node.isLeaf(), row, false);
				renderer.setSize(renderer.getPreferredSize());

				// move down the point in our graphics space into which we will paint
				yOffset += rowBounds.height;
				g.translate(0, rowBounds.height);
				renderer.paint(g);
			}
		}
		finally {
			// restore the point into graphics that we will paint
			g.translate(0, -yOffset);
		}
	}

	private List<GTreeNode> createSelectionList(TreePath[] selectionPaths) {

		List<GTreeNode> list = new ArrayList<GTreeNode>();

		if (selectionPaths == null) {
			return list;
		}

		for (int i = 0; i < selectionPaths.length; i++) {
			list.add((GTreeNode) selectionPaths[i].getLastPathComponent());
		}
		return list;
	}

//======================================================
// DropTarget method
//======================================================
	@Override
	public void dragEnter(DropTargetDragEvent dtde) {
		dragOver(dtde);
	}

	@Override
	public void dragExit(DropTargetEvent dte) {
		resetRenderer();
	}

	private void resetRenderer() {
		gTree.setActiveDropTargetNode(null);
		tree.repaint();
	}

	@Override
	public void dragOver(DropTargetDragEvent dtde) {
		tree.cancelEditing();

		Point dragLocation = dtde.getLocation();
		TreePath path = tree.getClosestPathForLocation(dragLocation.x, dragLocation.y);
		if (path == null) {
			return;  // no program open, so not even a root node available
		}

		gTree.setActiveDropTargetNode(null);
		tree.repaint();
		GTreeNode dropNode = (GTreeNode) path.getLastPathComponent();
		if (dragNDropHandler.isDropSiteOk(dropNode, dtde.getCurrentDataFlavors(),
			dtde.getDropAction())) {
			gTree.setActiveDropTargetNode(dropNode);
			dtde.acceptDrag(dtde.getDropAction());
			return;
		}
		dtde.rejectDrag();
	}

	@Override
	public void drop(DropTargetDropEvent dtde) {
		Point dragLocation = dtde.getLocation();
		TreePath path = tree.getClosestPathForLocation(dragLocation.x, dragLocation.y);

		GTreeNode dropNode = (GTreeNode) path.getLastPathComponent();
		dtde.acceptDrop(dtde.getDropAction());
		dragNDropHandler.drop(dropNode, dtde.getTransferable(), dtde.getDropAction());
		dtde.dropComplete(true);
		resetRenderer();
	}

	@Override
	public void dropActionChanged(DropTargetDragEvent dtde) {
		// don't care
	}
}
