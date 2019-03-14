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
package ghidra.app.plugin.core.datamgr.archive;

import ghidra.framework.plugintool.Plugin;
import ghidra.util.HelpLocation;
import ghidra.util.UniversalID;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;

import docking.DialogComponentProvider;

public class ChooseArchiveDialog extends DialogComponentProvider {

	private JPanel archiveListPanel;
	private JTextField filterField;
	private boolean removeWasCanceled;
	private Archive currentArchive;
	private List<Archive> archiveList;
	private JList list;
	private DefaultListModel listModel;

	public ChooseArchiveDialog(Plugin plugin, String title, Archive currentArchive,
			List<Archive> archiveList) {
		super(title);
		this.currentArchive = currentArchive;
		this.archiveList = archiveList;
		createArchiveListPanel();
		filterField = getFilterField();
		addWorkPanel(archiveListPanel);
		addOKButton();
		setOkToolTip("Choose the archive file to synchronize.");
		addCancelButton();
		setHelpLocation(new HelpLocation(plugin.getName(), "Choose_Archive"));
	}

	public boolean wasCanceled() {
		return removeWasCanceled;
	}

	@Override
	protected void cancelCallback() {
		removeWasCanceled = true;
		clearStatusText();
		close();
	}

	@Override
	protected void okCallback() {
		clearStatusText();
		Archive selectedArchive = getSelectedArchive();

		if (selectedArchive == null) {
			setStatusText("Please select an archive to synchronize.");
			return;
		}
		close();
		return;
	}

	/**
	 * Return the JList component.
	 */
	JList getList() {
		return list;
	}

	JTextField getFilterField() {
		return filterField;
	}

	/**
	 * Return the selected data type archive in the JList.
	 * @return null if no object is selected
	 */
	public Archive getSelectedArchive() {
		int index = list.getSelectedIndex();
		if (index >= 0) {
			return (Archive) listModel.get(index);
		}
		return null;
	}

	void selectArchive(Archive archive) {
		int index = listModel.indexOf(archive);
		list.setSelectedIndex(index);
	}

//    @Override
//    public void requestFocus() {
//        filterField.requestFocus();
//        filterField.selectAll();
//        filterList( filterField.getText() );
//    }

	private void createArchiveListPanel() {

		archiveListPanel = new JPanel(new BorderLayout());
		JPanel northPanel = new JPanel();
		String instructions =
			"<HTML>Choose the archive to synchronize with <B>" + currentArchive.getName() +
				"</B>.</HTML>";
		JLabel instructionLabel = new JLabel(instructions);
		northPanel.add(instructionLabel, BorderLayout.NORTH);
		northPanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 8, 3));
		archiveListPanel.add(northPanel, BorderLayout.NORTH);

		// Create the list 
		listModel = new DefaultListModel();
		initListModel();
		list = new JList(listModel);
		list.setCellRenderer(new MyListCellRenderer());
		list.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if ((e.getClickCount() == 2) && (e.getButton() == MouseEvent.BUTTON1)) {
					if (list.getSelectedValue() != null) {
						okCallback();
					}
				}
			}
		});

		// Set the preferred row count. This affects the preferredSize 
		// of the JList when it's in a scrollpane. 
		int size = listModel.getSize();
		list.setVisibleRowCount(size);

		JScrollPane scrollPane = new JScrollPane(list);
		scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		scrollPane.setBorder(BorderFactory.createEmptyBorder());

		JPanel southPanel = new JPanel();
		southPanel.setLayout(new BoxLayout(southPanel, BoxLayout.X_AXIS));

		filterField = createFilterField();
		southPanel.add(new JLabel("Filter: "));
		southPanel.add(filterField);
		southPanel.setBorder(BorderFactory.createEmptyBorder(8, 3, 8, 3));

		archiveListPanel.add(southPanel, BorderLayout.SOUTH);

		// Add list to a scrollpane 
		JPanel listPanel = new JPanel(new BorderLayout());
		listPanel.add(scrollPane, BorderLayout.CENTER);
		listPanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
		archiveListPanel.add(listPanel);
	}

	private JTextField createFilterField() {
		JTextField newFilterField = new JTextField(20);
//        newFilterField.setBackground( BACKGROUND_COLOR );
//        newFilterField.setBorder( BorderFactory.createEmptyBorder( 0, 0, 5, 0 ) );

		newFilterField.getDocument().addDocumentListener(new DocumentListener() {
			public void changedUpdate(DocumentEvent e) {
				filter(e.getDocument());
			}

			public void insertUpdate(DocumentEvent e) {
				filter(e.getDocument());
			}

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
		List<Archive> allDataList = new ArrayList<Archive>();
		allDataList.addAll(archiveList);

		boolean hasFilter = filterText.trim().length() != 0;
		if (hasFilter) {
			String lowerCaseFilterText = filterText.toLowerCase();
			for (Iterator<Archive> iterator = allDataList.iterator(); iterator.hasNext();) {
				Archive archive = iterator.next();
				String archiveString = getStringUsedInList(archive).toLowerCase();
				if (archiveString.indexOf(lowerCaseFilterText) < 0) {
					iterator.remove();
				}
			}
		}

		listModel.clear();
		for (Archive archive : allDataList) {
			listModel.addElement(archive);
		}

		// select something in the list so that the user can make a selection from the keyboard
		int totalListSize = archiveList.size();
		int shownListSize = listModel.getSize();
		if (shownListSize > 0) {
			int selectedIndex = list.getSelectedIndex();
			if (selectedIndex < 0) {
				list.setSelectedIndex(0);
			}
			if (shownListSize == totalListSize) {
				clearStatusText();
			}
			else {
				setStatusText("Filter is hiding " + (totalListSize - shownListSize) +
					" of the archive choices.");
			}
		}
		else {
			setStatusText("Filter is hiding all possible archive choices.");
		}
	}

	private String getStringUsedInList(Archive archive) {
		return archive.getName();
	}

	private void initListModel() {
		listModel.clear();
		for (int i = 0; i < archiveList.size(); i++) {
			Archive archive = archiveList.get(i);
			UniversalID sourceID = currentArchive.getDataTypeManager().getUniversalID();
			SourceArchive sourceArchive = archive.getDataTypeManager().getSourceArchive(sourceID);
			if (sourceArchive != null) {
				// This archive at least had a data type from the source archive at one time.
				listModel.addElement(archive);
			}
		}
	}

	private class MyListCellRenderer extends JLabel implements ListCellRenderer {

		MyListCellRenderer() {
			setOpaque(true);
		}

		/* (non-Javadoc)
		 * @see javax.swing.ListCellRenderer#getListCellRendererComponent(javax.swing.JList, java.lang.Object, int, boolean, boolean)
		 */
		public Component getListCellRendererComponent(JList localList, Object value, int index,
				boolean isSelected, boolean cellHasFocus) {

			Archive archive = (Archive) value;
			setIcon(archive.getIcon(false));
			setIconTextGap(5);

			String text = getStringUsedInList(archive);
			setText(text);
			if (isSelected) {
				setBackground(localList.getSelectionBackground());
				setForeground(localList.getSelectionForeground());
			}
			else {
				setBackground(localList.getBackground());
				setForeground(localList.getForeground());
			}
			setBorder(BorderFactory.createEmptyBorder(0, 3, 0, 10));
			return this;
		}
	}
}
