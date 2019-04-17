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
package ghidra.formats.gfilesystem;

import ghidra.util.SystemUtilities;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;
import java.util.function.Function;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.MultiLineLabel;
import docking.widgets.list.ListPanel;

/**
 * Dialog that presents the user with a list of strings and returns the object
 * associated with the user-picked element.
 * <p>
 * @param <T> opaque object type that will be selected by the user.
 */
public class SelectFromListDialog<T> extends DialogComponentProvider {

	/**
	 * Modally shows the user a dialog with a list of strings, and returns the picked object.
	 * <p>
	 * (automatically switches to Swing thread)
	 *
	 * @param list list of object of type T
	 * @param title title of dialog
	 * @param prompt prompt shown above list
	 * @param toStringFunc func that converts a T into a String.
	 * @return the chosen T object, or null if dialog canceled.
	 */
	public static <T> T selectFromList(List<T> list, String title, String prompt,
			Function<T, String> toStringFunc) {
		SelectFromListDialog<T> dialog =
			new SelectFromListDialog<>(title, prompt, list, toStringFunc);
		SystemUtilities.runSwingNow(() -> dialog.doSelect());
		return dialog.actionComplete ? dialog.getSelectedObject() : null;
	}

	private boolean actionComplete = false;
	private ListPanel listPanel;
	private T selectedObject;
	private List<T> list;
	private Function<T, String> toStringFunc;

	public SelectFromListDialog(String title, String prompt, List<T> list,
			Function<T, String> toStringFunc) {
		super(title, true);

		this.list = list;
		this.toStringFunc = toStringFunc;

		addWorkPanel(buildWorkPanel(prompt));
		addOKButton();
		addCancelButton();

		setDefaultButton(okButton);
	}

	@Override
	protected void okCallback() {
		if (checkInput()) {
			actionComplete = true;
			close();
		}
	}

	private boolean checkInput() {
		return listPanel.getSelectedIndex() != -1;
	}

	public T getSelectedObject() {
		return selectedObject;
	}

	private void doSelect() {
		selectedObject = null;
		actionComplete = false;
		DockingWindowManager activeInstance = DockingWindowManager.getActiveInstance();
		activeInstance.showDialog(this);
		if (actionComplete) {
			selectedObject = list.get(listPanel.getSelectedIndex());
		}
	}

	private JPanel buildWorkPanel(String prompt) {
		DefaultListModel<Object> listModel = new DefaultListModel<Object>() {
			@Override
			public String getElementAt(int index) {
				T t = (T) super.getElementAt(index);
				return toStringFunc.apply(t);
			}

		};

		for (T obj : list) {
			listModel.addElement(obj);
		}

		listPanel = new ListPanel();
		listPanel.setListModel(listModel);
		listPanel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		listPanel.setSelectedIndex(0);
		listPanel.setDoubleClickActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				okCallback();
			}
		});

		JPanel workPanel = new JPanel(new BorderLayout());
		MultiLineLabel mll = new MultiLineLabel("\n" + prompt + ":");
		workPanel.add(mll, BorderLayout.NORTH);
		workPanel.add(listPanel, BorderLayout.CENTER);
		return workPanel;
	}
}
