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
package docking.widgets;

import java.awt.event.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;

import javax.swing.JTree;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

public class JTreeMouseListenerDelegate extends MouseAdapter {

	private final Set<MouseListener> listeners = new CopyOnWriteArraySet<>();
	private final JTree tree;

	private boolean consumedPressed;

	public JTreeMouseListenerDelegate(JTree tree) {
		this.tree = tree;

		installMouseListenerDelegate();

		tree.addMouseListener(this);
	}

	private void installMouseListenerDelegate() {
		MouseListener[] mouseListeners = tree.getMouseListeners();
		List<MouseListener> list = Arrays.asList(mouseListeners);
		listeners.addAll(list);
		for (MouseListener listener : mouseListeners) {
			tree.removeMouseListener(listener);
		}
	}

	public MouseListener[] getMouseListeners() {
		if (listeners.isEmpty()) {
			return new MouseListener[0];
		}
		return listeners.toArray(new MouseListener[listeners.size()]);
	}

	public void addMouseListener(MouseListener listener) {
		listeners.add(listener);
	}

	public void removeMouseListener(MouseListener listener) {
		listeners.remove(listener);
	}

	public void addMouseListeners(List<MouseListener> listenerList) {
		this.listeners.addAll(listenerList);
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		for (MouseListener listener : listeners) {
			listener.mouseEntered(e);
		}
	}

	@Override
	public void mouseExited(MouseEvent e) {
		for (MouseListener listener : listeners) {
			listener.mouseExited(e);
		}
	}

	@Override
	public void mousePressed(MouseEvent e) {
		handlePopupTrigger(e);
		if (isPotentialDragSelection(e)) {
			e.consume();
			consumedPressed = true;

			// ensure the tree has focus in this case, since we consumed the event, which can
			// prevent the normal focus updating done by Swing
			fixFocus();
		}
		else {
			consumedPressed = false;
		}
		fireMousePressed(e);
	}

	private void fixFocus() {
		if (!tree.hasFocus()) {
			tree.requestFocus();
		}
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		handlePopupTrigger(e);
		fireMouseClicked(e);
		consumedPressed = false;
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		if (!handlePopupTrigger(e)) {
			// Potentially clear any residue of where we may have 
			// clicked a multi-selection, but did not actually perform a drag
			maybeResetSelectionPath(e);
		}
		fireMouseReleased(e);
	}

	protected void fireMousePressed(MouseEvent e) {
		for (MouseListener listener : listeners) {
			listener.mousePressed(e);
		}
	}

	protected void fireMouseClicked(MouseEvent e) {
		for (MouseListener listener : listeners) {
			listener.mouseClicked(e);
		}
	}

	protected void fireMouseReleased(MouseEvent e) {
		for (MouseListener listener : listeners) {
			listener.mouseReleased(e);
		}
	}

	protected boolean handlePopupTrigger(MouseEvent e) {
		if (!e.isPopupTrigger()) {
			return false;
		}

		TreePath selPath = tree.getPathForLocation(e.getX(), e.getY());
		if (selPath != null) {
			if (!tree.isPathSelected(selPath)) {
				setSelectedPathNow(selPath);
			}
		}
		return true;
	}

	private void maybeResetSelectionPath(MouseEvent e) {
		if (!consumedPressed) {
			return;
		}

		TreePath clickedPath = tree.getPathForLocation(e.getX(), e.getY());
		if (clickedPath == null) {
			return;
		}

		setSelectedPathNow(clickedPath);
	}

	// have you clicked on a place that you may want to drag?
	protected boolean isPotentialDragSelection(MouseEvent e) {
		if (e.getButton() == MouseEvent.BUTTON1) {
			if (e.getClickCount() > 1) {
				return false;
			}
			if (e.isControlDown() || e.isAltDown() || e.isShiftDown() || e.isMetaDown()) {
				return false;
			}

			TreePath selectionPath = tree.getPathForLocation(e.getX(), e.getY());
			if (selectionPath == null) {
				return false;
			}

			// don't let other process the event if we are 'pressing' the mouse button on an 
			// already selected node (to prevent de-selecting a multi-selection)
			if (tree.isPathSelected(selectionPath)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * This method is overridden by subclasses.
	 */
	protected void setSelectedPathNow(TreePath path) {
		TreeSelectionModel treeSelectionModel = tree.getSelectionModel();
		treeSelectionModel.setSelectionPath(path);
	}
}
