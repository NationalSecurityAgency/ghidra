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
package ghidra.app.plugin.core.progmgr;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionAdapter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;

import docking.widgets.list.GListCellRenderer;
import ghidra.program.model.listing.Program;

/**
 * Panel that displays the overflow of currently open programs that can be choosen.
 * <p>
 * Programs that don't have a visible tab are displayed in bold. 
 */
class ProgramListPanel extends JPanel {

	private static final Color BACKGROUND_COLOR = new Color(255, 255, 230);
	private List<Program> hiddenList;
	private List<Program> shownList;
	private JList<Program> programList;
	private MultiTabPlugin multiTabPlugin;
	private DefaultListModel<Program> listModel;
	private JTextField filterField;

	/**
	 * Construct a new ObjectListPanel.
	 * @param hiddenList list of Programs that are not showing (tabs are not visible)
	 * @param shownList list of Programs that are that are showing
	 * @param multiTabPlugin has info about the program represented by a tab
	 */
	ProgramListPanel(List<Program> hiddenList, List<Program> shownList,
			MultiTabPlugin multiTabPlugin) {
		super(new BorderLayout());
		this.hiddenList = hiddenList;
		this.shownList = shownList;
		this.multiTabPlugin = multiTabPlugin;
		create();
	}

	/**
	 * Set the object lists.
	 * @param hiddenList list of Objects that are not showing (tabs are not visible)
	 * @param shownList list of Objects that are showing
	 */
	void setProgramLists(List<Program> hiddenList, List<Program> shownList) {
		this.hiddenList = hiddenList;
		this.shownList = shownList;
		initListModel();
		programList.clearSelection();
	}

	/**
	 * Return the JList component.
	 */
	JList<Program> getList() {
		return programList;
	}

	JTextField getFilterField() {
		return filterField;
	}

	/**
	 * Return the selected Object in the JList.
	 * @return null if no object is selected
	 */
	Program getSelectedProgram() {
		int index = programList.getSelectedIndex();
		if (index >= 0) {
			return listModel.get(index);
		}
		return null;
	}

	void selectProgram(Program program) {
		int index = listModel.indexOf(program);
		programList.setSelectedIndex(index);
	}

	@Override
	public void requestFocus() {
		filterField.requestFocus();
		filterField.selectAll();
		filterList(filterField.getText());
	}

	private void create() {

		listModel = new DefaultListModel<>();
		initListModel();
		programList = new JList<>(listModel);
		programList.setBackground(BACKGROUND_COLOR);
		programList.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
		programList.addMouseMotionListener(new MouseMotionAdapter() {
			@Override
			public void mouseMoved(MouseEvent e) {
				int index = programList.locationToIndex(e.getPoint());
				if (index >= 0) {
					programList.setSelectedIndex(index);
				}
			}
		});

		programList.setCellRenderer(new ProgramListCellRenderer());
		JScrollPane sp = new JScrollPane();
		sp.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		sp.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		sp.setBorder(BorderFactory.createEmptyBorder());

		JPanel northPanel = new JPanel();
		northPanel.setLayout(new BoxLayout(northPanel, BoxLayout.Y_AXIS));

		filterField = createFilterField();
		northPanel.add(filterField);

		JSeparator separator = new JSeparator();
		northPanel.add(separator);
		northPanel.setBackground(BACKGROUND_COLOR);

		add(northPanel, BorderLayout.NORTH);
		add(programList, BorderLayout.CENTER);

		// add some padding around the panel
		Border innerBorder = BorderFactory.createEmptyBorder(5, 5, 5, 5);
		Border outerBorder = BorderFactory.createLineBorder(Color.BLACK);
		Border compoundBorder = BorderFactory.createCompoundBorder(outerBorder, innerBorder);
		setBorder(compoundBorder);

		setBackground(BACKGROUND_COLOR);
	}

	private JTextField createFilterField() {
		JTextField newFilterField = new JTextField(20);
		newFilterField.setBackground(BACKGROUND_COLOR);
		newFilterField.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));

		newFilterField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent e) {
				filter(e.getDocument());
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				filter(e.getDocument());
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				filter(e.getDocument());
			}

			private void filter(Document document) {
				try {
					String text = document.getText(0, document.getLength());
					filterList(text);
				}
				catch (BadLocationException e) {
					// shouldn't happen; don't care
				}
			}
		});

		return newFilterField;
	}

	private void filterList(String filterText) {
		List<Program> allDataList = new ArrayList<>();
		allDataList.addAll(hiddenList);
		allDataList.addAll(shownList);

		boolean hasFilter = filterText.trim().length() != 0;
		if (hasFilter) {
			String lowerCaseFilterText = filterText.toLowerCase();
			for (Iterator<Program> iterator = allDataList.iterator(); iterator.hasNext();) {
				Program program = iterator.next();
				String programString = multiTabPlugin.getStringUsedInList(program).toLowerCase();
				if (programString.indexOf(lowerCaseFilterText) < 0) {
					iterator.remove();
				}
			}
		}

		listModel.clear();
		for (Program program : allDataList) {
			listModel.addElement(program);
		}

		// select something in the list so that the user can make a selection from the keyboard
		if (listModel.getSize() > 0) {
			int selectedIndex = programList.getSelectedIndex();
			if (selectedIndex < 0) {
				programList.setSelectedIndex(0);
			}
		}
	}

	private void initListModel() {
		listModel.clear();
		for (int i = 0; i < hiddenList.size(); i++) {
			listModel.addElement(hiddenList.get(i));
		}
		for (int i = 0; i < shownList.size(); i++) {
			listModel.addElement(shownList.get(i));
		}
	}

	private class ProgramListCellRenderer extends GListCellRenderer<Program> {

		@Override
		protected String getItemText(Program program) {
			return multiTabPlugin.getStringUsedInList(program);
		}

		@Override
		public Component getListCellRendererComponent(JList<? extends Program> list, Program value,
				int index, boolean isSelected, boolean hasFocus) {
			super.getListCellRendererComponent(list, value, index, isSelected, hasFocus);

			if (hiddenList.contains(value)) {
				setBold();
			}
			if (isSelected) {
				setBackground(list.getSelectionBackground());
				setForeground(list.getSelectionForeground());
			}
			else {
				setBackground(list.getBackground());
				setForeground(list.getForeground());
			}

			return this;
		}
	}
}
