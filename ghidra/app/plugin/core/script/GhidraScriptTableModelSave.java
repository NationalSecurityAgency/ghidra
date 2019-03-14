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
package ghidra.app.plugin.core.script;

import java.io.File;
import java.util.*;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import docking.KeyEntryTextField;
import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.TableSortingContext;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.ScriptInfo;
import ghidra.util.DateUtils;
import resources.Icons;

class GhidraScriptTableModelSave extends AbstractSortedTableModel<ResourceFile> {

	private static final String EMPTY_STRING = "";
	private static final ImageIcon ERROR_IMG = Icons.ERROR_ICON;

	final static int SCRIPT_ACTION_COL = 0;
	final static int STATUS_COL = 1;
	final static int NAME_COL = 2;
	final static int DESCRIPTION_COL = 3;
	final static int KEYBINDING_COL = 4;
	final static int FULL_PATH_COL = 5;
	final static int CATEGORY_COL = 6;
	final static int MODIFIED_COL = 7;

	private GhidraScriptComponentProvider provider;
	private List<ResourceFile> scriptList = new ArrayList<>();

	GhidraScriptTableModelSave(GhidraScriptComponentProvider provider) {
		super(NAME_COL);
		this.provider = provider;
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	protected void sort(List<ResourceFile> data, TableSortingContext<ResourceFile> sortingContext) {
		ResourceFile script = provider.getSelectedScript(); // remember the selected script
		super.sort(data, sortingContext);
		provider.setSelectedScript(script);
	}

	@Override
	public String getName() {
		return "Scripts";
	}

	@Override
	public void fireTableDataChanged() {
		super.fireTableDataChanged();
	}

	boolean contains(int row) {
		return row >= 0 && row < scriptList.size();
	}

	int getScriptIndex(ResourceFile script) {
		return scriptList.indexOf(script);
	}

	List<ResourceFile> getScripts() {
		return new ArrayList<>(scriptList);
	}

	ResourceFile getScriptAt(int row) {
		if (row < 0 || row > scriptList.size() - 1) {
			return null;
		}
		return scriptList.get(row);
	}

	void insertScript(ResourceFile script) {
		if (!scriptList.contains(script)) {
			int row = scriptList.size();
			scriptList.add(script);
			fireTableRowsInserted(row, row);
		}
	}

	void insertScripts(List<ResourceFile> scriptFiles) {
		for (ResourceFile script : scriptFiles) {
			if (!scriptList.contains(script)) {
				scriptList.add(script);
			}
		}
		fireTableDataChanged();
	}

	void removeScript(ResourceFile script) {
		int row = scriptList.indexOf(script);
		if (row >= 0) {
			scriptList.remove(row);

			fireTableRowsDeleted(row, row);
		}
	}

	void removeScripts(Collection<File> scripts) {
		for (File script : scripts) {
			int row = scriptList.indexOf(script);
			if (row >= 0) {
				scriptList.remove(row);
			}
		}
		fireTableDataChanged();
	}

	void switchScript(ResourceFile oldScript, ResourceFile newScript) {
		int index = scriptList.indexOf(oldScript);
		if (index != -1) {
			scriptList.set(index, newScript);
			fireTableRowsUpdated(index, index);
		}
	}

	@Override
	public int getRowCount() {
		if (scriptList == null) {
			return 0;
		}
		return scriptList.size();
	}

	@Override
	public int getColumnCount() {
		return COL_NAMES.length;
	}

	@Override
	public String getColumnName(int column) {
		return COL_NAMES[column];
	}

	final static String[] COL_NAMES = new String[] { "In Tool", "Status", "Filename", "Description",
		"Key Binding", "Full Path", "Category", "Last Modified" };

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		switch (columnIndex) {
			case SCRIPT_ACTION_COL:
				return Boolean.class;
			case STATUS_COL:
				return ImageIcon.class;
			case NAME_COL:
				return String.class;
			case DESCRIPTION_COL:
				return String.class;
			case KEYBINDING_COL:
				return KeyBindingsInfo.class;
			case FULL_PATH_COL:
				return String.class;
			case CATEGORY_COL:
				return String.class;
			case MODIFIED_COL:
				return String.class;
		}
		return Object.class;
	}

	@Override
	public boolean isCellEditable(int row, int column) {
		if (column == SCRIPT_ACTION_COL) {
			return true;
		}
		return false;
	}

	@Override
	public void setValueAt(Object value, int row, int column) {
		if (column == SCRIPT_ACTION_COL) {
			ResourceFile script = getScriptAt(row);
			if ((Boolean) value) {
				provider.getActionManager().createAction(script);
			}
			else {
				provider.getActionManager().removeAction(script);
			}
		}
		fireTableCellUpdated(row, column);
	}

	@Override
	public Object getColumnValueForRow(ResourceFile script, int columnIndex) {
		ScriptInfo info = GhidraScriptUtil.getScriptInfo(script);
		switch (columnIndex) {
			case SCRIPT_ACTION_COL:
				return provider.getActionManager().hasScriptAction(info.getSourceFile());
			case STATUS_COL:
				if (info != null) {
					if (info.isCompileErrors() || info.isDuplicate()) {
						return ERROR_IMG;
					}
					return info.getToolBarImage(true);
				}
				return null;
			case NAME_COL:
				return info.getName();
			case DESCRIPTION_COL:
				if (info != null) {
					return info.getDescription();
				}
				return null;
			case KEYBINDING_COL:
				KeyStroke actionKeyStroke = provider.getActionManager().getKeyBinding(script);
				boolean isActionBinding = false;
				KeyStroke keyBinding = info.getKeyBinding();
				if (actionKeyStroke != null) {
					keyBinding = actionKeyStroke;
					isActionBinding = true;
				}

				String errorMessage = info.getKeyBindingErrorMessage();
				if (errorMessage != null) {
					return new KeyBindingsInfo(isActionBinding, keyBinding, errorMessage);
				}
				return new KeyBindingsInfo(isActionBinding, keyBinding);
			case FULL_PATH_COL:
				return info.getSourceFile().getAbsolutePath();
			case CATEGORY_COL:
				return getCategoryString(info);
			case MODIFIED_COL:
				return DateUtils.formatDate(new Date(script.lastModified()));
		}
		return "<unknown script>";
	}

	private String getCategoryString(ScriptInfo info) {
		String[] category = info.getCategory();
		if (category.length == 0) {
			return EMPTY_STRING;
		}

		StringBuilder buffy = new StringBuilder();
		for (String string : category) {
			buffy.append(string).append('-').append('>');
		}

		buffy.delete(buffy.length() - 2, buffy.length()); // strip off last separator

		return buffy.toString();
	}

	@Override
	public List<ResourceFile> getModelData() {
		return scriptList;
	}

	@Override
	protected Comparator<ResourceFile> createSortComparator(int columnIndex) {
		return new ScriptComparator(columnIndex);
	}

	private class ScriptComparator implements Comparator<ResourceFile> {
		private final int sortedColumn;

		public ScriptComparator(int columnIndex) {
			this.sortedColumn = columnIndex;
		}

		@Override
		public int compare(ResourceFile script1, ResourceFile script2) {
			ScriptInfo info1 = GhidraScriptUtil.getScriptInfo(script1);
			ScriptInfo info2 = GhidraScriptUtil.getScriptInfo(script2);
			int value = 0;
			switch (sortedColumn) {
				case SCRIPT_ACTION_COL:
					boolean isScriptAction1 =
						provider.getActionManager().hasScriptAction(info1.getSourceFile());
					boolean isScriptAction2 =
						provider.getActionManager().hasScriptAction(info2.getSourceFile());
					if (isScriptAction1 == isScriptAction2) {
						value = script1.getName().compareToIgnoreCase(script2.getName());
						break;
					}
					if (isScriptAction1) {
						value = -1;
					}
					else {
						value = 1;
					}
					break;
				case STATUS_COL: {
					if (!info1.isCompileErrors() && info2.isCompileErrors()) {
						value = -1;
						break;
					}
					else if (info1.isCompileErrors() && !info2.isCompileErrors()) {
						value = 1;
						break;
					}
					value = 0;
					break;
				}
				case NAME_COL: {
					value = script1.getName().compareToIgnoreCase(script2.getName());
					break;
				}
				case DESCRIPTION_COL: {
					String d1 = info1.getDescription();
					String d2 = info2.getDescription();
					value = d1.compareTo(d2);
					break;
				}
				case KEYBINDING_COL: {
					KeyStroke ks1 =
						provider.getActionManager().getKeyBinding(info1.getSourceFile());
					KeyStroke ks2 =
						provider.getActionManager().getKeyBinding(info2.getSourceFile());
					String s1 = ks1 == null ? "" : KeyEntryTextField.parseKeyStroke(ks1);
					String s2 = ks2 == null ? "" : KeyEntryTextField.parseKeyStroke(ks2);
					value = s1.compareToIgnoreCase(s2);
					break;
				}
				case FULL_PATH_COL: {
					value =
						script1.getAbsolutePath().compareToIgnoreCase(script2.getAbsolutePath());
					break;
				}
				case CATEGORY_COL: {
					value = getCategoryString(info1).compareToIgnoreCase(getCategoryString(info2));
					break;
				}
				case MODIFIED_COL: {
					value = Long.compare(script1.lastModified(), script2.lastModified());
					break;
				}

			}
			return value;
		}
	}
}
