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
package ghidra.app.plugin.core.programtree;

import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.*;
import java.awt.event.KeyEvent;
import java.util.EventObject;

import javax.swing.*;
import javax.swing.tree.*;

import docking.DockingUtils;
import docking.actions.KeyBindingUtils;
import docking.dnd.*;
import docking.widgets.table.AutoscrollAdapter;

/**
 * Class to support Drag and Drop; it is also responsible for
 * rendering the icons, and  for editing a node name.
 * <p>The nodes that are used in this class are ProgramNode objects.</p>
 */
public abstract class DragNDropTree extends JTree implements Draggable, Droppable, Autoscroll {

	private AutoscrollAdapter autoscroller;

	protected DefaultTreeModel treeModel;
	protected DragSource dragSource;
	protected DragGestureAdapter dragGestureAdapter;
	protected TreeDragSrcAdapter dragSourceAdapter;
	protected int dragAction = DnDConstants.ACTION_COPY_OR_MOVE;

	protected DropTarget dropTarget;
	protected DropTgtAdapter dropTargetAdapter;
	protected ProgramNode root;
	protected ProgramTreeCellEditor cellEditor;
	protected Color plafSelectionColor;
	protected DnDTreeCellRenderer dndCellRenderer;
	protected boolean drawFeedback;
	protected ProgramNode[] draggedNodes; // node being transferred
	protected ProgramNode destinationNode; // target for drop site

	// data flavors that this tree can support
	protected DataFlavor[] acceptableFlavors; // filled in by the
	// getAcceptableDataFlavors() method

	protected TreeTransferable transferable;
	protected Color nonSelectionDragColor;
	protected int relativeMousePos; // mouse position within the node:

	// -1 --> above node,
	//  0 --> at the node
	//  1 --> below the node

	/**
	 * Construct a new DragNDropTree.
	 */
	public DragNDropTree(DefaultTreeModel model) {
		super(model);
		treeModel = model;
		this.root = (ProgramNode) model.getRoot();
		//setEditable(true); // edit interferes with drag gesture listener

		setShowsRootHandles(true);  // need this to "drill down"
		cellEditor = new ProgramTreeCellEditor();
		setCellEditor(cellEditor);
		dndCellRenderer = new DnDTreeCellRenderer();
		setCellRenderer(dndCellRenderer);
		plafSelectionColor = dndCellRenderer.getBackgroundSelectionColor();
		nonSelectionDragColor = new Color(204, 204, 255);
		initDragNDrop();
		ToolTipManager.sharedInstance().registerComponent(this);
		autoscroller = new AutoscrollAdapter(this, getRowHeight());
		disableJTreeTransferActions();
	}

	//// Draggable interface methods
	/**
	 * Return true if the location in the event is draggable.
	 */
	@Override
	public boolean isStartDragOk(DragGestureEvent e) {
		synchronized (root) {
			Point p = e.getDragOrigin();
			ProgramNode node = getTreeNode(p);
			if (node == null || node.equals(root)) {
				return false;
			}
			if (isEditing()) {
				stopEditing();
			}
			return true;
		}
	}

	/**
	 * Called by the DragGestureAdapter to start the drag.
	 */
	@Override
	public DragSourceListener getDragSourceListener() {
		return dragSourceAdapter;
	}

	/**
	 * Called by the DragGestureAdapter and the DragSourceAdapter to
	 * know what actions this component allows.
	 */
	@Override
	public int getDragAction() {
		return DnDConstants.ACTION_COPY_OR_MOVE;
	}

	/**
	 * Called by the DragGestureAdapter when the drag is about to
	 * start.
	 */
	@Override
	public Transferable getTransferable(Point p) {
		synchronized (root) {
			TreePath[] selectionPaths = getSelectionPaths();
			if (selectionPaths == null || selectionPaths.length == 0) {
				return null;
			}

			ProgramNode[] nodes = new ProgramNode[selectionPaths.length];
			for (int i = 0; i < nodes.length; i++) {
				nodes[i] = (ProgramNode) selectionPaths[i].getLastPathComponent();
			}

			transferable = new TreeTransferable(nodes);
			draggedNodes = nodes;
			return transferable;
		}
	}

	/**
	 * Do the move operation. Called from the DragSourceAdapter
	 * when the drop completes and the user action was a
	 * DnDConstants.MOVE.
	 */
	@Override
	public abstract void move();

	/**
	 * Called from the DragSourceAdapter when the drag operation exits the
	 * drop target without dropping.
	 */
	@Override
	public void dragCanceled(DragSourceDropEvent event) {
		draggedNodes = null;
		dndCellRenderer.setBackgroundSelectionColor(plafSelectionColor);
		dndCellRenderer.setBackgroundNonSelectionColor(dndCellRenderer.getBackgroundNonSelectionColor());
	}

	//////////////////////////////////////////////////////////////////////
	// Droppable interface methods
	/**
	 * Return true if OK to drop at the location specified in the event.
	 */
	@Override
	public boolean isDropOk(DropTargetDragEvent e) {
		synchronized (root) {
			Point p = e.getLocation();
			ProgramNode targetNode = getTreeNode(p);
			if (isEditing()) {
				stopEditing();
			}

			if (targetNode == null) {
				return false;
			}

			if (dragSelectionContainsTarget(targetNode)) {
				return false;
			}

			if (draggedNodes == null) {
				// could be another kind of transferable
				return isDropSiteOk(targetNode, e);
			}

			// This is tree node transferable... 
			if (draggedNodes.equals(root)) {
				return false;
			}

			return !dragSelectionContainsDescendant(targetNode);
		}
	}

	private boolean dragSelectionContainsTarget(ProgramNode targetNode) {
		if (draggedNodes == null) {
			return false;
		}

		for (int i = 0; i < draggedNodes.length; i++) {
			if (targetNode.equals(draggedNodes[i])) {
				return true;
			}
		}
		return false;
	}

	private boolean dragSelectionContainsDescendant(ProgramNode targetNode) {
		if (draggedNodes == null) {
			return false;
		}

		for (int i = 0; i < draggedNodes.length; i++) {
			if (targetNode.isNodeAncestor(draggedNodes[i])) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Called from the DropTgtAdapter when the drag operation is going over a drop site; indicate 
	 * when the drop is OK by providing appropriate feedback. 
	 * @param ok true means OK to drop
	 */
	@Override
	public void dragUnderFeedback(boolean ok, DropTargetDragEvent e) {
		synchronized (root) {
			drawFeedback = true;
			cancelEditing();
			if (ok) {
				Point p = e.getLocation();
				TreePath path = getPathForLocation(p.x, p.y);
				if (path == null) {
					return;
				}
				destinationNode = (ProgramNode) path.getLastPathComponent();
				relativeMousePos = comparePointerLocation(p, destinationNode);
				int action = e.getDropAction();
				dragSourceAdapter.setFeedbackCursor(null);

				Cursor c = dragSourceAdapter.getDropOkCursor(action);
				if (relativeMousePos != 0) {
					drawFeedback = false;
					c = dragSourceAdapter.getCursor(action, relativeMousePos);
				}
				else {
					dndCellRenderer.setSelectionForDrag(plafSelectionColor);
					dndCellRenderer.setNonSelectionForDrag(nonSelectionDragColor);
				}
				dragSourceAdapter.setFeedbackCursor(c);
			}
			else {
				destinationNode = null;
				dndCellRenderer.setSelectionForDrag(Color.red);
				dndCellRenderer.setNonSelectionForDrag(Color.red);
			}
			Point p = e.getLocation();
			dndCellRenderer.setRowForFeedback(getRowForLocation(p.x, p.y));
			repaint();
		}
	}

	/**
	 * Called from the DropTgtAdapter to revert any feedback
	 * changes back to normal.
	 */
	@Override
	public void undoDragUnderFeedback() {
		synchronized (root) {
			drawFeedback = false;
		}
		repaint();
	}

	/**
	 * Add the data to the tree. Called from the DropTgtAdapter
	 * when the drop completes and the user action was a
	 * DnDConstants.COPY.
	 */
	@Override
	public abstract void add(Object data, DropTargetDropEvent e, DataFlavor chosen);

	///////////////////////////////////////////////////////////
	// Autoscroll Interface methods
	///////////////////////////////////////////////////////////
	/**
	 * This method returns the <code>Insets</code> describing
	 * the autoscrolling region or border relative
	 * to the geometry of the implementing Component; called
	 * repeatedly while dragging.
	 * @return the Insets
	 */
	@Override
	public Insets getAutoscrollInsets() {
		return autoscroller.getAutoscrollInsets();
	}

	/**
	 * Notify the <code>Component</code> to autoscroll; called repeatedly
	 * while dragging.
	 * <P>
	 * @param p A <code>Point</code> indicating the
	 * location of the cursor that triggered this operation.
	 */

	@Override
	public void autoscroll(Point p) {
		autoscroller.autoscroll(p);
	}

	///////////////////////////////////////////////////////////////
	// protected methods
	///////////////////////////////////////////////////////////////
	/**
	 * Get the data flavors that this tree supports.
	 */
	protected abstract DataFlavor[] getAcceptableDataFlavors();

	/**
	 * Return true if the node can accept the drop as indicated by the event.
	 * @param e event that has current state of drag and drop operation 
	 * @return true if drop is OK
	 */
	protected abstract boolean isDropSiteOk(ProgramNode node, DropTargetDragEvent e);

	/**
	 * Get the string to use as the tool tip for the specified node.
	 */
	protected abstract String getToolTipText(ProgramNode node);

	/**
	 * Get the node at the given point.
	 * @return null if there is no node a the point p.
	 */
	protected ProgramNode getTreeNode(Point p) {
		TreePath path = getPathForLocation(p.x, p.y);
		if (path != null) {
			return (ProgramNode) path.getLastPathComponent();
		}
		return null;
	}

	/**
	 * Return the drawFeedback state.
	 */
	boolean getDrawFeedbackState() {
		return drawFeedback;
	}

	//////////////////////////////////////////////////////////////////////
	// *** private methods
	//////////////////////////////////////////////////////////////////////

	/**
	 * Set up the drag and drop stuff.
	 */
	private void initDragNDrop() {

		acceptableFlavors = getAcceptableDataFlavors();

		// set up drop stuff
		dropTargetAdapter =
			new DropTgtAdapter(this, DnDConstants.ACTION_COPY_OR_MOVE, acceptableFlavors);
		dropTarget =
			new DropTarget(this, DnDConstants.ACTION_COPY_OR_MOVE, dropTargetAdapter, true);
		dropTarget.setActive(true);

		// set up drag stuff
		dragSource = DragSource.getDefaultDragSource();
		dragGestureAdapter = new DragGestureAdapter(this);
		dragSourceAdapter = new TreeDragSrcAdapter(this);
		dragSource.createDefaultDragGestureRecognizer(this, dragAction, dragGestureAdapter);
	}

	private void disableJTreeTransferActions() {
		KeyBindingUtils.clearKeyBinding(this,
			KeyStroke.getKeyStroke(KeyEvent.VK_C, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		KeyBindingUtils.clearKeyBinding(this,
			KeyStroke.getKeyStroke(KeyEvent.VK_V, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		KeyBindingUtils.clearKeyBinding(this,
			KeyStroke.getKeyStroke(KeyEvent.VK_X, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
	}

	/**
	 * Determine where the mouse pointer is within the node.
	 * @return -1 if the mouse pointer is in the upper quarter of the node, 1 if the mouse pointer 
	 *  is in the lower quarter of the node, or 0 if the mouse pointer is in the center of the node.
	 */
	int comparePointerLocation(Point p, ProgramNode node) {

		int localRowHeight = getRowHeight();
		int row = this.getRowForPath(node.getTreePath());
		Rectangle rect = getRowBounds(row);
		if (p.y == rect.y) {
			return 1;
		}
		if ((p.y - rect.y) <= localRowHeight) {
			int delta = localRowHeight - (p.y - rect.y);
			int sliceSize = localRowHeight / 4;
			if (delta < sliceSize) {
				return 1; // in the lower part of the node
			}
			if (delta > (sliceSize * 3)) {
				return -1; // in the upper part of the node
			}
		}
		return 0;
	}

	//////////////////////////////////////////////////////////////////////
	/**
	 * TreeCellEditor for the program tree.
	 */
	protected class ProgramTreeCellEditor extends DefaultTreeCellEditor {

		/**
		 * Construct a new ProgramTreeCellEditor.
		 */
		public ProgramTreeCellEditor() {
			super(DragNDropTree.this, null);
		}

		/**
		 * Override this method in order to select the contents of
		 * the editing component which is a JTextField.
		 */
		@Override
		public boolean shouldSelectCell(EventObject anEvent) {
			((JTextField) editingComponent).selectAll();
			return super.shouldSelectCell(anEvent);
		}
	}
}
