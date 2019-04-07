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
package docking;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.plaf.basic.BasicSeparatorUI;
import javax.swing.text.Document;
import javax.swing.text.JTextComponent;
import javax.swing.undo.UndoableEdit;

import ghidra.docking.util.DockingWindowsLookAndFeelUtils;
import resources.ResourceManager;

public class DockingUtils {

	private static final int ICON_SIZE = 16;

	/** System dependent mask for the Ctrl key */
	public static final int CONTROL_KEY_MODIFIER_MASK =
		Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();

	/**
	 * A version the control key modifiers that is based upon the pre-Java 9 {@link InputEvent}
	 * usage.  This mask is here for those clients that cannot be upgraded, such as those with 
	 * dependencies on 3rd-party libraries that still use the old mask style.
	 * 
	 * @deprecated use instead {@link #CONTROL_KEY_MODIFIER_MASK} 
	 */
	@Deprecated
	public static final int CONTROL_KEY_MODIFIER_MASK_DEPRECATED =
		((CONTROL_KEY_MODIFIER_MASK & InputEvent.META_DOWN_MASK) == InputEvent.META_DOWN_MASK)
				? InputEvent.META_MASK
				: InputEvent.CTRL_MASK;

	public static final String CONTROL_KEY_NAME =
		((CONTROL_KEY_MODIFIER_MASK & InputEvent.META_DOWN_MASK) == InputEvent.META_DOWN_MASK)
				? "Command"
				: "Control";

	private static final KeyStroke UNDO_KEYSTROKE =
		KeyStroke.getKeyStroke(KeyEvent.VK_Z, CONTROL_KEY_MODIFIER_MASK);
	private static final KeyStroke REDO_KEYSTROKE =
		KeyStroke.getKeyStroke(KeyEvent.VK_Y, CONTROL_KEY_MODIFIER_MASK);

	public static JSeparator createToolbarSeparator() {
		Dimension sepDim = new Dimension(2, ICON_SIZE + 2);
		JSeparator separator = new JSeparator(SwingConstants.VERTICAL);
		if (DockingWindowsLookAndFeelUtils.isUsingAquaUI(separator.getUI())) {
			separator.setUI(new BasicSeparatorUI());
		}
		separator.setPreferredSize(sepDim); // ugly work around to force height of separator
		return separator;
	}

	public static Icon scaleIconAsNeeded(Icon icon) {
		if (icon == null) {
			return null;
		}

		if (icon.getIconHeight() != DockingUtils.ICON_SIZE ||
			icon.getIconWidth() != DockingUtils.ICON_SIZE) {

			return ResourceManager.getScaledIcon(icon, ICON_SIZE, ICON_SIZE);
		}

		return icon;
	}

	/**
	 * Checks if the mouseEvent has the "control" key down.  On windows, this is actually
	 * the <tt>control</tt> key.  On Mac, it is the <tt>command</tt> key.
	 * 
	 * @param mouseEvent the event to check 
	 * @return true if the control key is pressed
	 */
	public static boolean isControlModifier(MouseEvent mouseEvent) {
		int modifiers = mouseEvent.getModifiersEx();
		int osSpecificMask = CONTROL_KEY_MODIFIER_MASK;
		return (modifiers & osSpecificMask) == osSpecificMask;
	}

	/**
	 * Checks if the mouseEvent has the "control" key down.  On windows, this is actually
	 * the <tt>control</tt> key.  On Mac, it is the <tt>command</tt> key.
	 * 
	 * @param keyEvent the event to check 
	 * @return true if the control key is pressed
	 */
	public static boolean isControlModifier(KeyEvent keyEvent) {
		int modifiers = keyEvent.getModifiersEx();
		int osSpecificMask = CONTROL_KEY_MODIFIER_MASK;
		return (modifiers & osSpecificMask) == osSpecificMask;
	}

	public static UndoRedoKeeper installUndoRedo(JTextComponent textComponent) {

		Document document = textComponent.getDocument();

		final UndoRedoKeeper undoRedoKeeper = new UndoRedoKeeper();
		document.addUndoableEditListener(e -> {
			UndoableEdit edit = e.getEdit();

// TODO We are now handed a wrapper class and not the event for the 'edit'.  It is not clear
//		which use case caused this code to be added.  If/when we find out, we can revisit how 
//		to filter these types of updates.
//			DefaultDocumentEvent defaultDocumentEvent = (DefaultDocumentEvent) edit;
//			if (defaultDocumentEvent.getType() == EventType.CHANGE) {
//				return; // this happens for style updates
//			}

			undoRedoKeeper.addUndo(edit);
		});

		// need a key listener
		textComponent.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				KeyStroke keyStrokeForEvent = KeyStroke.getKeyStrokeForEvent(e);
				if (REDO_KEYSTROKE.equals(keyStrokeForEvent)) {
					undoRedoKeeper.redo();
				}
				else if (UNDO_KEYSTROKE.equals(keyStrokeForEvent)) {
					undoRedoKeeper.undo();
				}
			}
		});

		return undoRedoKeeper;
	}

	/**
	 * A callback to operate on a component
	 * @param <T> the type of component on which to operate
	 * @see DockingUtils#forAllDescendants(Container, Class, TreeTraversalOrder, ComponentCallback)
	 */
	public static interface ComponentCallback<T extends Component> {
		TreeTraversalResult call(T component);
	}

	/**
	 * Specifies the order of component traversal
	 * @see DockingUtils#forAllDescendants(Container, Class, TreeTraversalOrder, ComponentCallback)
	 */
	public enum TreeTraversalOrder {
		CHILDREN_FIRST, PARENT_FIRST;
	}

	/**
	 * Controls traversal and communicates cause for termination
	 * @see DockingUtils#forAllDescendants(Container, Class, TreeTraversalOrder, ComponentCallback)
	 */
	public enum TreeTraversalResult {
		CONTINUE, FINISH, TERMINATE;
	}

	/**
	 * Perform some operation on a component and all of its descendants, recursively
	 * 
	 * This traverses the swing/awt component tree starting at the given container and descends
	 * recursively through all containers. Any time a component of type (or subclass of type) is
	 * found, the given callback is executed on it. If order is
	 * {@link TreeTraversalOrder#CHILDREN_FIRST}, then the traversal will execute the callback on
	 * the children of a container before executing the callback on the container itself; if
	 * {@link TreeTraversalOrder#PARENT_FIRST}, then the traversal will execute the callback on the
	 * container before descending.
	 * 
	 * The callback must return one of three result values. In normal circumstances, it should
	 * return {@link TreeTraversalResult#CONTINUE}, allowing traversal to continue to the next
	 * element. If the callback wishes to terminate traversal "successfully," e.g., because it
	 * needed to locate the first element satisfying some predicate, then it should return
	 * {@link TreeTraversalResult#FINISH}. If an error occurs during traversal, then it should
	 * either return {@link TreeTraversalResult#TERMINATE} or throw an appropriate exception to
	 * terminate traversal "unsuccessfully."
	 * 
	 * This method will also return a value of {@link TreeTraversalResult} indicating how traversal
	 * terminated. If {@link TreeTraversalResult#CONTINUE}, then every element in the subtree was
	 * visited, and traversal was successful. If {@link TreeTraversalResult#FINISH}, then some
	 * elements may have been omitted, but traversal was still successful. If
	 * {@link TreeTraversalResult#TERMINATE}, then some elements may have been omitted, and
	 * traversal was not successful.
	 * 
	 * @param start the "root" container of the subtree on which to operate
	 * @param type the type of components on which to operate
	 * @param order whether to operation on children or parents first
	 * @param cb the callback to perform the actual operation
	 * @return a result indicating whether or not traversal completed successfully
	 */
	@SuppressWarnings("unchecked")
	public static <T extends Component> TreeTraversalResult forAllDescendants(Container start,
			Class<T> type, TreeTraversalOrder order, ComponentCallback<T> cb) {
		for (Component c : start.getComponents()) {
			if (TreeTraversalOrder.PARENT_FIRST == order) {
				if (type.isAssignableFrom(c.getClass())) {
					TreeTraversalResult res = cb.call((T) c);
					if (TreeTraversalResult.FINISH == res || TreeTraversalResult.TERMINATE == res) {
						return res;
					}
				}
			}
			if (c instanceof Container) {
				TreeTraversalResult res = forAllDescendants((Container) c, type, order, cb);
				if (TreeTraversalResult.FINISH == res || TreeTraversalResult.TERMINATE == res) {
					return res;
				}
			}
			if (TreeTraversalOrder.CHILDREN_FIRST == order) {
				if (type.isAssignableFrom(c.getClass())) {
					TreeTraversalResult res = cb.call((T) c);
					if (TreeTraversalResult.FINISH == res || TreeTraversalResult.TERMINATE == res) {
						return res;
					}
				}
			}
		}
		return TreeTraversalResult.CONTINUE;
	}

	/**
	 * Perform some operation on a component and all of its descendents, recursively.
	 * 
	 * This applies the operation to all components in the tree, children first.
	 * 
	 * @param start the "root" container of the subtree on which to operate
	 * @param cb the callback to perform the actual operation
	 * @return a result indicating whether or not traversal completed successfully
	 * @see DockingUtils#forAllDescendants(Container, Class, TreeTraversalOrder, ComponentCallback)
	 */
	public static TreeTraversalResult forAllDescendants(Container start,
			ComponentCallback<Component> cb) {
		return forAllDescendants(start, Component.class, TreeTraversalOrder.CHILDREN_FIRST, cb);
	}

	/**
	 * Sets the given component to transparent, which allows the parent component's background
	 * to be painted.
	 * <p>
	 * <u>Notes</u>
	 * Historically, to make a component transparent you would call 
	 * {@link JComponent#setOpaque(boolean)} with a <tt>false</tt> value.  However, it turns out
	 * that the definition and the implementation of this method are at odds.  <tt>setOpaque(false)</tt>
	 * is meant to signal that some part of the component is transparent, so the parent component
	 * needs to be painted.  Most LaFs implemented this by not painting the background of the
	 * component, but used the parent's color instead.  The Nimbus LaF actually honors the 
	 * contract of <tt>setOpaque()</tt>, which has the effect of painting the components 
	 * background by default.
	 * <p>
	 * This method allows components to achieve transparency when they used to 
	 * rely on <tt>setOpaque(false)</tt>.
	 * 
	 * @param c the component to be made transparent
	 */
	public static void setTransparent(JComponent c) {

		doSetTransparent(c);

		if (c instanceof JScrollPane) {
			doSetTransparent(((JScrollPane) c).getViewport());
		}
	}

	private static void doSetTransparent(JComponent c) {
		// transparent...
		c.setOpaque(false);

		// ...I really mean it!
		if (!(c instanceof JViewport)) {
			// ugly, I know, but you cannot do this
			c.setBorder(BorderFactory.createEmptyBorder());
		}

		c.setBackground(new Color(0, 0, 0, 0));
	}

}
