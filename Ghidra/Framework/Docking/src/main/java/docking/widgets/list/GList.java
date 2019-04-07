/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.Vector;

import javax.swing.JList;
import javax.swing.ListModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import docking.widgets.table.GTable;

/**
 * A sub-class of JList that provides an auto-lookup feature.
 * The user can begin typing the first few letters of a desired
 * list element and the selection will automatically navigate to it.
 */
public class GList<T> extends JList<T> {
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
		addKeyListener(new KeyListener() {
			public void keyPressed(KeyEvent e) {
//				if (e.isActionKey() ||
//				    e.getKeyChar() == KeyEvent.CHAR_UNDEFINED ||
//				    Character.isISOControl(e.getKeyChar())) {
//				    return;
//				}
//				long when = e.getWhen();
//				if (when - lastLookupTime > KEY_TIMEOUT) {
//				    lookupString = ""+e.getKeyChar();
//				}
//				else {
//				    lookupString += ""+e.getKeyChar();
//				}
//				int index = getIndex(getModel(), lookupString);
//				if (index >= 0) {
//				    setSelectedIndex(index);
//				    Rectangle rect = getCellBounds(index, index);
//				    scrollRectToVisible(rect);
//				}
//				lastLookupTime = when;
//				e.consume();
			}

			public void keyReleased(KeyEvent e) {
			}

			public void keyTyped(KeyEvent e) {
			}
		});
		addListSelectionListener(new ListSelectionListener() {
			public void valueChanged(ListSelectionEvent e) {
				ensureIndexIsVisible(getSelectedIndex());
			}
		});
	}

}
