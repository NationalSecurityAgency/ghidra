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
/*
 * Created on Aug 7, 2006
 */
package ghidra.app.util.bean;

import java.awt.BorderLayout;
import java.awt.Rectangle;
import java.awt.event.*;
import java.util.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableColumnModel;

import docking.widgets.label.GLabel;
import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.TableSortingContext;
import ghidra.program.model.lang.*;
import ghidra.util.table.GhidraTable;

/**
 * A generic reusable panel for selecting a language.
 * Also, supports a filter to limit languages that are displayed.
 */
public class SelectLanguagePanel extends JPanel {
	private static final long serialVersionUID = 1L;

	public static void main(String[] args) {
		SelectLanguagePanel slp = new SelectLanguagePanel(null);
		JDialog dialog = new JDialog(new JFrame(), "Select Language Panel");
		dialog.getContentPane().setLayout(new BorderLayout());
		dialog.getContentPane().add(slp, BorderLayout.CENTER);
		dialog.pack();
		dialog.setVisible(true);
	}

	private GhidraTable table;
	private LanguageModel model;
	private JTextField filterField;

	/**
	 * Constructs a new panel.
	 * @param service the language service to use to retrieve the languages
	 */
	public SelectLanguagePanel(LanguageService service) {
		super();

		model = new LanguageModel(service);

		table = new GhidraTable(model);
		table.setAutoLookupColumn(LanguageModel.NAME_COL);
		table.setName("LanguageTable");//for testing...
		table.setRowSelectionAllowed(true);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);

		table.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					e.consume();
				}
			}
		});

		TableColumnModel tcm = table.getColumnModel();
		tcm.getColumn(LanguageModel.NAME_COL).setPreferredWidth(250);
		tcm.getColumn(LanguageModel.PROCESSOR_COL).setPreferredWidth(75);
		tcm.getColumn(LanguageModel.MANUFACTURER_COL).setPreferredWidth(75);

		filterField = new JTextField();
		filterField.setName("SET_LANG_FILTER");//for testing...
		filterField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent e) {
				filter();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				filter();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				filter();
			}
		});
		filterField.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				filterField.selectAll();
			}
		});

		JPanel filterPanel = new JPanel(new BorderLayout());
		filterPanel.add(new GLabel("Filter:"), BorderLayout.WEST);
		filterPanel.add(filterField, BorderLayout.CENTER);

		setLayout(new BorderLayout(10, 10));
		add(new JScrollPane(table), BorderLayout.CENTER);
		add(filterPanel, BorderLayout.SOUTH);

		model.update();
	}

	/**
	 * Allows language versions to appear appended to name
	 * @param enable
	 */
	public void setShowVersion(boolean enable) {
		model.setShowVersion(enable);
		model.fireTableDataChanged();
	}

	/**
	 * Selects the language with the specified language ID.
	 * @param languageID the ID of language to select
	 */
	public void setSelectedLanguage(LanguageID languageID) {
		if (model.service == null) {
			return;
		}
		Language lang = null;
		try {
			lang = model.service.getLanguage(languageID);
		}
		catch (LanguageNotFoundException e) {
		}
		setSelectedLanguage(lang);
	}

	public void setSelectedLanguage(Language lang) {
		if (model.contains(lang)) {
			int row = model.getRow(lang);
			table.setRowSelectionInterval(row, row);
			Rectangle rect = table.getCellRect(row, LanguageModel.NAME_COL, true);
			table.scrollRectToVisible(rect);
		}
		else {
			table.clearSelection();
		}
	}

	public void setLanguageService(LanguageService service) {
		model.service = service;
		update();
	}

	public void dispose() {
		model.dispose();
	}

	/**
	 * Update the panel. Requests a new list of languages from the
	 * language service and updates the table.
	 *
	 */
	public void update() {
		model.update();
	}

	/**
	 * Returns the selected language, or null if no language is selected.
	 * @return the selected language, or null if no language is selected.
	 */
	public Language getSelectedLanguage() {
		int row = table.getSelectedRow();
		return model.getLanguage(row);
	}

	/**
	 * Sets the filter string.
	 * @param filter the string to filter on
	 * @return the number of languages that matched the filter
	 */
	public int setFilter(String filter) {
		filterField.setText(filter);//this will kick the document listener
		return model.getRowCount();
	}

	/**
	 * Select the highest priority language being displayed.
	 * If more than one language has the highest priority, then the first
	 * one will be used.
	 */
	public void selectHighestPriorityLanguage() {
		Language lang = model.getHighestPriority();
		setSelectedLanguage(lang);
	}

	private void filter() {
		String filter = filterField.getText();
		model.filter(filter);
	}

	private class LanguageModel extends AbstractSortedTableModel<LanguageDescription> {
		private final static int NAME_COL = 0;
		private final static int PROCESSOR_COL = 1;
		private final static int MANUFACTURER_COL = 2;

		private final static int NO_FILTER = 0;
		private final static int STARTS_WITH_FILTER = 1;
		private final static int ENDS_WITH_FILTER = 2;
		private final static int EQUALS_FILTER = 3;
		private final static int CONTAINS_FILTER = 4;

		private LanguageService service;
		private LanguageDescription[] masterList = new LanguageDescription[0];
		private List<LanguageDescription> displayList = new ArrayList<>();
		private String filter;
		private int filterType = NO_FILTER;
		private boolean showVersion = false;

		private LanguageModel(LanguageService service) {
			super(NAME_COL);
			this.service = service;
		}

		void setShowVersion(boolean enable) {
			showVersion = enable;
		}

		@Override
		public boolean isSortable(int columnIndex) {
			return true;
		}

		@Override
		protected void sort(List<LanguageDescription> data,
				TableSortingContext<LanguageDescription> sortingContext) {

			Language selectedLang = getSelectedLanguage();
			super.sort(data, sortingContext);
			setSelectedLanguage(selectedLang);
		}

		private Language getHighestPriority() {
			if (displayList.isEmpty()) {
				return null;
			}
			LanguageDescription supremeLang = null;
			for (LanguageDescription ld : displayList) {
				if (supremeLang == null) {
					supremeLang = ld;
				}
			}
			if (supremeLang == null) {
				return null;
			}
			try {
				return service.getLanguage(supremeLang.getLanguageID());
			}
			catch (LanguageNotFoundException e) {
				return null;
			}
		}

		private boolean contains(Language lang) {
			if (lang == null) {
				return false;
			}
			return getRow(lang) >= 0;
		}

		private int getRow(Language lang) {
			if (lang == null) {
				return -1;
			}
			int index = 0;
			for (LanguageDescription ld : displayList) {
				if (ld.getLanguageID().equals(lang.getLanguageID())) {
					return index;
				}
				++index;
			}
			return -1;
		}

		private Language getLanguage(int row) {
			if (row < 0 || row >= getRowCount()) {
				return null;
			}
			if (service == null) {
				return null;
			}
			LanguageDescription languageDescription = displayList.get(row);
			LanguageID id = languageDescription.getLanguageID();
			try {
				if (service instanceof VersionedLanguageService) {
					return ((VersionedLanguageService) service).getLanguage(id,
						languageDescription.getVersion());
				}
				return service.getLanguage(id);
			}
			catch (LanguageNotFoundException e) {
			}
			return null;
		}

		@Override
		public void dispose() {
			service = null;
			update();
		}

		private void filter(String f) {
			if (f == null) {
				filterType = NO_FILTER;
			}
			else {
				if (f.length() > 1 && f.startsWith("\"") && f.endsWith("\"")) {
					filterType = EQUALS_FILTER;
					filter = f.substring(1, f.length() - 1);
				}
				else if (f.startsWith("\"")) {
					filterType = STARTS_WITH_FILTER;
					filter = f.substring(1, f.length());
				}
				else if (f.endsWith("\"")) {
					filterType = ENDS_WITH_FILTER;
					filter = f.substring(0, f.length() - 1);
				}
				else {
					filterType = CONTAINS_FILTER;
					filter = f;
				}
				filter = filter.toLowerCase();
			}
			filter();
		}

		private boolean matchesFilter(String str) {
			switch (filterType) {
				case STARTS_WITH_FILTER:
					return str.toLowerCase().startsWith(filter);
				case ENDS_WITH_FILTER:
					return str.toLowerCase().endsWith(filter);
				case EQUALS_FILTER:
					return str.equalsIgnoreCase(filter);
				case CONTAINS_FILTER:
					return str.toLowerCase().indexOf(filter) >= 0;
			}
			return true;
		}

		private void filter() {
			Language selectedLang = getSelectedLanguage();
			displayList.clear();
			if (filter == null) {
				displayList.addAll(Arrays.asList(masterList));
			}
			else {
				for (LanguageDescription element : masterList) {
					if (matchesFilter(element.getLanguageID().getIdAsString()) ||
						matchesFilter(element.getProcessor().toString())) {
						displayList.add(element);
					}
				}
			}

			fireTableDataChanged();
			setSelectedLanguage(selectedLang);
		}

		@Override
		protected Comparator<LanguageDescription> createSortComparator(int columnIndex) {
			return new LanguageDescriptionComparator(columnIndex);
		}

		private void update() {
			if (service == null) {
				masterList = new LanguageDescription[0];
			}
			else {
				masterList =
					service.getLanguageDescriptions(false).toArray(new LanguageDescription[0]);
			}
			filter();
		}

		@Override
		public Class<String> getColumnClass(int aColumn) {
			return String.class;
		}

		@Override
		public int getRowCount() {
			return displayList.size();
		}

		private String getLanguageDisplayName(LanguageDescription ld) {
			LanguageID id = ld.getLanguageID();
			String langDisplayName = id.toString();
			if (showVersion) {
				langDisplayName =
					id.toString() + " (" + ld.getVersion() + "." + ld.getMinorVersion() + ")";
			}
			return langDisplayName;
		}

		@Override
		public String getName() {
			return "Select Language";
		}

		@Override
		public int getColumnCount() {
			return 3;
		}

		@Override
		public String getColumnName(int aColumn) {
			switch (aColumn) {
				case NAME_COL:
					return "Name";
				case PROCESSOR_COL:
					return "Processor";
				case MANUFACTURER_COL:
					return "Manufacturer";
			}
			return "Unknown";
		}

		@Override
		public Object getColumnValueForRow(LanguageDescription ld, int columnIndex) {
			switch (columnIndex) {
				case NAME_COL:
					return getLanguageDisplayName(ld);
				case PROCESSOR_COL:
					return ld.getProcessor().toString();
			}
			return "Unknown";
		}

		@Override
		public List<LanguageDescription> getModelData() {
			return displayList;
		}

		class LanguageDescriptionComparator implements Comparator<LanguageDescription> {
			private final int sortColumn;

			public LanguageDescriptionComparator(int sortColumn) {
				this.sortColumn = sortColumn;
			}

			@Override
			public int compare(LanguageDescription ld1, LanguageDescription ld2) {
				int value = 0;
				switch (sortColumn) {
					case NAME_COL:
						value = getLanguageDisplayName(ld1).compareTo(getLanguageDisplayName(ld2));
						break;
					case PROCESSOR_COL:
						value =
							ld1.getProcessor().toString().compareTo(ld2.getProcessor().toString());
						break;
				}
				return value;
			}
		}
	}
}
