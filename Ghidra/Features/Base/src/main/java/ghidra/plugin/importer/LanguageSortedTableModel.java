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
package ghidra.plugin.importer;

import java.util.*;

import docking.widgets.table.AbstractSortedTableModel;
import ghidra.program.model.lang.*;

public class LanguageSortedTableModel extends AbstractSortedTableModel<LanguageCompilerSpecPair> {

	final static int PROCESSOR_COL = 0;
	final static int VARIANT_COL = 1;
	final static int SIZE_COL = 2;
	final static int ENDIAN_COL = 3;
	final static int COMPILER_SPEC_COL = 4;

	final static String[] COL_NAMES =
		new String[] { "Processor", "Variant", "Size", "Endian", "Compiler", };

	private List<LanguageCompilerSpecPair> languageList = new ArrayList<>();

	void setLanguages(List<LanguageCompilerSpecPair> languageList) {
		this.languageList = languageList;
		if (languageList == null) {
			this.languageList = Collections.emptyList();
		}
		this.fireTableDataChanged();
	}

	@Override
	public String getName() {
		return "Languages";
	}

	@Override
	public int getColumnCount() {
		return COL_NAMES.length;
	}

	@Override
	public String getColumnName(int column) {
		try {
			return COL_NAMES[column];
		}
		catch (Exception e) {
			return "<<unknown>>";
		}
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		switch (columnIndex) {
			case PROCESSOR_COL:
				return Processor.class;
			case VARIANT_COL:
				return String.class;
			case SIZE_COL:
				return Integer.class;
			case ENDIAN_COL:
				return Endian.class;
			case COMPILER_SPEC_COL:
				return CompilerSpecDescription.class;
		}
		return Object.class;
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public List<LanguageCompilerSpecPair> getModelData() {
		return languageList;
	}

	@Override
	public Object getColumnValueForRow(LanguageCompilerSpecPair pair, int column) {
		try {
			switch (column) {
				case PROCESSOR_COL:
					return pair.getLanguageDescription().getProcessor();
				case VARIANT_COL:
					return pair.getLanguageDescription().getVariant();
				case SIZE_COL:
					return pair.getLanguageDescription().getSize();
				case ENDIAN_COL:
					return pair.getLanguageDescription().getEndian();
				case COMPILER_SPEC_COL:
					return pair.getCompilerSpecDescription();
			}
		}
		catch (LanguageNotFoundException e) {
			return "<LanguageNotFound>";
		}
		catch (CompilerSpecNotFoundException e) {
			return "<CompilerSpecNotFound>";
		}
		return "<unknown value>";
	}

	public LanguageCompilerSpecPair getLcsPairAtRow(int selectedRow) {
		if (languageList == null || selectedRow < 0 || selectedRow >= languageList.size()) {
			return null;
		}
		return languageList.get(selectedRow);
	}

	public int getFirstLcsPairIndex(LanguageCompilerSpecPair toFind) {
		if (languageList != null) {
			int index = 0;
			for (LanguageCompilerSpecPair pair : languageList) {
				if (pair.equals(toFind)) {
					return index;
				}
				++index;
			}
		}
		return -1;
	}
}
