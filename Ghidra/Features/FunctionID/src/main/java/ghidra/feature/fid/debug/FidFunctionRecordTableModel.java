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
package ghidra.feature.fid.debug;

import java.util.List;

import docking.widgets.table.AbstractSortedTableModel;
import ghidra.feature.fid.db.*;

/**
 *  The table model for the match results panel when searching for FID function records.
 */
public class FidFunctionRecordTableModel extends AbstractSortedTableModel<FunctionRecord> {
	static final int NAME_COL = 0;
	static final int FID_COL = 1;
	static final int LIB_COL = 2;
	static final int PATH_COL = 3;
	static final int FH_COL = 4;
	static final int CUS_COL = 5;
	static final int XH_COL = 6;
	static final int XHS_COL = 7;
	static final int WARN_COL = 8;

	private final FidQueryService service;
	private List<FunctionRecord> functionRecords;

	/**
	 * Create the table model.
	 * @param service the FID database service
	 * @param functionRecords the function records to display
	 */
	public FidFunctionRecordTableModel(FidQueryService service,
			List<FunctionRecord> functionRecords) {
		this.service = service;
		this.functionRecords = functionRecords;
	}

	@Override
	public String getName() {
		return "Fid Functions";
	}

	/**
	 * Returns if this model is sortable (true).
	 */
	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	/**
	 * Returns the number of columns (WARN_COL + 1).
	 */
	@Override
	public int getColumnCount() {
		return WARN_COL + 1;
	}

	/**
	 * Returns the model data.
	 */
	@Override
	public List<FunctionRecord> getModelData() {
		return functionRecords;
	}

	public void resetWholeTable(List<FunctionRecord> newRecords) {
		functionRecords = newRecords;
		fireTableDataChanged();
	}

	/**
	 * Returns the column class, which is a string (unless we're on the hash sizes which is integer).
	 */
	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnIndex == CUS_COL || columnIndex == XHS_COL) {
			return Integer.class;
		}
		return String.class;
	}

	/**
	 * Returns the column name.
	 */
	@Override
	public String getColumnName(int column) {
		switch (column) {
			case FID_COL:
				return "Function ID";
			case LIB_COL:
				return "Library";
			case PATH_COL:
				return "Domain Path";
			case NAME_COL:
				return "Name";
			case FH_COL:
				return "Full Hash";
			case CUS_COL:
				return "Code Unit Size";
			case XH_COL:
				return "Specific Hash";
			case XHS_COL:
				return "Spec. +Size";
			case WARN_COL:
				return "Warn";
		}
		return "<<UNKNOWN>>";
	}

	/**
	 * Returns the column value.
	 */
	@Override
	public Object getColumnValueForRow(FunctionRecord t, int columnIndex) {
		switch (columnIndex) {
			case FID_COL:
				return String.format("0x%016x", t.getID());
			case LIB_COL:
				LibraryRecord libraryRecord = service.getLibraryForFunction(t);
				return String.format("%s %s %s", libraryRecord.getLibraryFamilyName(),
					libraryRecord.getLibraryVersion(), libraryRecord.getLibraryVariant());
			case PATH_COL:
				return t.getDomainPath();
			case NAME_COL:
				return t.getName();
			case FH_COL:
				return String.format("0x%016x", t.getFullHash());
			case CUS_COL:
				return Integer.valueOf(t.getCodeUnitSize());
			case XH_COL:
				return String.format("0x%016x", t.getSpecificHash());
			case XHS_COL:
				return Integer.valueOf(t.getSpecificHashAdditionalSize());
			case WARN_COL:
				// warning column can raise three different flags:
				// F, which means the record automatically fails
				// P, which means this record automatically passes
				// U, which means the function body was unterminated (likely analysis error)
				// S, which means this record can only be matched if the specific hash matches
				// R, which means this record can only be matched if a parent/child also matches
				return String.format("%s%s%s%s%s", t.autoFail() ? "F" : " ",
					t.autoPass() ? "P" : " ", t.hasTerminator() ? " " : "U",
					t.isForceSpecific() ? "S" : " ", t.isForceRelation() ? "R" : " ");
		}
		return "<<INTERNAL ERROR>>";
	}
}
