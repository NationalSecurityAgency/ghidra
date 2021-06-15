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

import java.util.List;

import javax.swing.JComponent;

import docking.DialogComponentProvider;
import docking.widgets.table.GTableWidget;

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
		addOKButton();
		addCancelButton();
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

	public void setFilterText(String text) {
		table.setFilterText(text);
	}

	@Override
	public void close() {
		table.dispose();
		super.close();
	}
}
