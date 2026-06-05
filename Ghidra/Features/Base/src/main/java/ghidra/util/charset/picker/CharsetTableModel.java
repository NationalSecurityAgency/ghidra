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
package ghidra.util.charset.picker;

import java.lang.Character.UnicodeScript;
import java.util.*;

import docking.widgets.table.AbstractSortedTableModel;
import ghidra.util.charset.CharsetInfo;
import ghidra.util.charset.CharsetInfoManager;

class CharsetTableModel extends AbstractSortedTableModel<CharsetTableRow> {

	final static int NAME_COL = 0;
	final static int COMMENT_COL = 1;
	final static int FIXEDLEN_COL = 2;
	final static int MINLEN_COL = 3;
	final static int MAXLEN_COL = 4;
	final static int SCRIPTS_COL = 5;

	final static String[] COL_NAMES =
		new String[] { "Name", "Description", "Fixed Length", "Min BPC", "Max BPC", "Scripts" };

	private List<CharsetTableRow> charsets = new ArrayList<>();

	public CharsetTableModel() {
		CharsetInfoManager.getInstance()
				.getCharsets()
				.stream()
				.map(csi -> new CharsetTableRow(csi, getScriptsString(csi.getScripts())))
				.forEach(charsets::add);
	}

	private static String getScriptsString(Set<UnicodeScript> scripts) {
		StringBuilder sb = new StringBuilder();
		for (UnicodeScript script : scripts) {
			if (!sb.isEmpty()) {
				sb.append(", ");
			}
			sb.append(script.name());
		}
		return sb.toString();
	}

	public int findCharset(CharsetInfo csi) {
		for (int i = 0; i < charsets.size(); i++) {
			CharsetTableRow row = charsets.get(i);
			if (row.csi().getName().equals(csi.getName())) {
				return i;
			}
		}
		return -1;
	}

	@Override
	public String getName() {
		return "Charsets";
	}

	@Override
	public int getColumnCount() {
		return COL_NAMES.length;
	}

	@Override
	public String getColumnName(int column) {
		return 0 <= column && column < COL_NAMES.length ? COL_NAMES[column] : "<<unknown>>";
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		switch (columnIndex) {
			case NAME_COL:
				return String.class;
			case COMMENT_COL:
				return String.class;
			case FIXEDLEN_COL:
				return Boolean.class;
			case MINLEN_COL:
				return Integer.class;
			case MAXLEN_COL:
				return Integer.class;
			case SCRIPTS_COL:
				return String.class;
		}
		return Object.class;
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public List<CharsetTableRow> getModelData() {
		return charsets;
	}

	@Override
	public Object getColumnValueForRow(CharsetTableRow row, int column) {
		return switch (column) {
			case NAME_COL -> row.csi().getName();
			case COMMENT_COL -> row.csi().getComment();
			case FIXEDLEN_COL -> row.csi().hasFixedLengthChars();
			case MINLEN_COL -> row.csi().getMinBytesPerChar();
			case MAXLEN_COL -> row.csi().getMaxBytesPerChar();
			case SCRIPTS_COL -> row.scripts();
			default -> "???";
		};
	}

}
