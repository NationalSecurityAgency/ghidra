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
package docking.widgets.dialogs;

import java.awt.Dimension;
import java.util.List;

import javax.swing.JComponent;

import docking.DialogComponentProvider;
import docking.widgets.table.GTable;
import docking.widgets.table.GTableWidget;

/**
 * Dialog for choosing from a list of objects.  The dialog uses a list of specified methods on the 
 * objects to form the columns of a display table, where each row in the table represents one of the
 * object to pick from.
 * 
 * @param <T> the object type of the object to choose from
 */
public class ObjectChooserDialog<T> extends DialogComponentProvider {

	private T selectedObject;
	private List<T> choosableObjects;
	private String[] methodsForColumns;
	private Class<T> objectClass;
	private GTableWidget<T> table;

	public ObjectChooserDialog(String title, Class<T> objectClass, List<T> choosableObjects,
			String... methodsForColumns) {
		super(title, true);
		this.objectClass = objectClass;
		this.choosableObjects = choosableObjects;
		this.methodsForColumns = methodsForColumns;

		setTransient(true);
		addWorkPanel(buildWorkPanel());
		table.addSelectionListener(t -> setOkEnabled(t != null));
		addOKButton();
		addCancelButton();
		setOkEnabled(false);
	}

	@Override
	protected void okCallback() {
		close();
	}

	@Override
	protected void cancelCallback() {
		selectedObject = null;
		close();
	}

	@Override
	protected void dialogShown() {
		table.focusFilter();
	}

	public GTableWidget<T> getTable() {
		return table;
	}

	private JComponent buildWorkPanel() {
		table = new GTableWidget<>(getTitle(), objectClass, methodsForColumns);
		table.setData(choosableObjects);

		table.addSelectionListener(t -> objectSelected(t));

		table.setItemPickListener(t -> objectPicked(t));
		table.getAccessibleContext().setAccessibleName("Object Chooser");
		return table;
	}

	protected void objectPicked(T t) {
		this.selectedObject = t;
		close();
	}

	protected void objectSelected(T t) {
		this.selectedObject = t;
		setOkEnabled(selectedObject != null);
	}

	public T getSelectedObject() {
		return selectedObject;
	}

	public void setSelectedObject(T t) {
		table.selectRowObject(t);
	}

	public void setFilterText(String text) {
		table.setFilterText(text);
	}

	public void setPreferredColumnWidths(int... widths) {
		table.setColumnPreferredWidths(widths);
	}

	public void setPreferredWidth(int width) {
		GTable gTable = table.getTable();
		Dimension vpSize = gTable.getPreferredScrollableViewportSize();
		int height = (int) vpSize.getHeight();
		Dimension newVpSize = new Dimension(width, height);
		gTable.setPreferredScrollableViewportSize(newVpSize);
	}

	public void setPreferredHeight(int height) {
		GTable gTable = table.getTable();
		Dimension vpSize = gTable.getPreferredScrollableViewportSize();
		int width = (int) vpSize.getWidth();
		Dimension newVpSize = new Dimension(width, height);
		gTable.setPreferredScrollableViewportSize(newVpSize);
	}

	@Override
	public void close() {
		table.dispose();
		super.close();
	}
}
