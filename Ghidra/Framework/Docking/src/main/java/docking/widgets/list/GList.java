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
package docking.widgets.list;

import java.util.Vector;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import docking.widgets.GComponent;
import docking.widgets.table.GTable;

/**
 * A sub-class of JList that provides an auto-lookup feature.
 * <p>
 * The user can begin typing the first few letters of a desired
 * list element and the selection will automatically navigate to it.
 * <p>
 * HTML rendering is disabled by default.
 * <p>
 * 
 */
public class GList<T> extends JList<T> implements GComponent {
	private static final long serialVersionUID = 1L;

	/**The timeout for the auto-lookup feature*/
	public static final long KEY_TIMEOUT = GTable.KEY_TIMEOUT;//made public for JUnits...

	/**
	 * Constructs a <code>GhidraList</code> with an empty model.
	 */
	public GList() {
		super();
		init();
	}

	/**
	 * Constructs a <code>GhidraList</code> that displays the elements in
	 * the specified array.  This constructor just delegates to the
	 * <code>ListModel</code> constructor.
	 * @param  listData  the array of Objects to be loaded into the data model
	 */
	public GList(T[] listData) {
		super(listData);
		init();
	}

	/**
	 * Constructs a <code>GhidraList</code> that displays the elements in
	 * the specified <code>Vector</code>.  This constructor just
	 * delegates to the <code>ListModel</code> constructor.
	 * @param  listData  the <code>Vector</code> to be loaded into the data model
	 */
	public GList(Vector<T> listData) {
		super(listData);
		init();
	}

	/**
	 * Constructs a <code>GhidraList</code> that displays the elements in the
	 * specified, non-<code>null</code> model. 
	 * All <code>GhidraList</code> constructors delegate to this one.
	 * @param dataModel   the data model for this list
	 * @exception IllegalArgumentException   if <code>dataModel</code> is <code>null</code>
	 */
	public GList(ListModel<T> dataModel) {
		super(dataModel);
		init();
	}

	private void init() {
		setHTMLRenderingEnabled(false);
		if (getCellRenderer() instanceof JComponent) {
			GComponent.setHTMLRenderingFlag((JComponent) getCellRenderer(), false);
		}
		addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				ensureIndexIsVisible(getSelectedIndex());
			}
		});
	}

//	/**
//	 * Turns off the HTML rendering in the specified component and its current cell renderer.
//	 * 
//	 * @param list the list
//	 */
//	public static void turnOffHTMLRendering(JList<?> list) {
//		turnOffHTMLRendering((JComponent) list);
//		if (list.getCellRenderer() instanceof JComponent) {
//			turnOffHTMLRendering((JComponent) list.getCellRenderer());
//		}
//	}

}
