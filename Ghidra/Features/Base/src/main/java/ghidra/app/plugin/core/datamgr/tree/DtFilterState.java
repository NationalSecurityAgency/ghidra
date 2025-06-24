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
package ghidra.app.plugin.core.datamgr.tree;

import java.util.Objects;

import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.framework.options.SaveState;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Function;

/**
 * A simple object to store various filter settings for the data type provider.
 */
public class DtFilterState {

	private static final String XML_NAME = "DATA_TYPES_FILTER";

	private DtTypeFilter arraysFilter = new DtTypeFilter("Arrays");
	private DtTypeFilter enumsFilter = new DtTypeFilter("Enums");
	private DtTypeFilter functionsFilter = new DtTypeFilter("Functions");
	private DtTypeFilter structuresFilter = new DtTypeFilter("Structures");
	private DtTypeFilter pointersFilter = new DtTypeFilter("Pointers");
	private DtTypeFilter unionsFilter = new DtTypeFilter("Unions");

	public DtFilterState() {
		// these types are off by default, since users typically are not working with them
		arraysFilter.setTypeActive(false);
		pointersFilter.setTypeActive(false);
	}

	public DtFilterState copy() {
		DtFilterState filterState = new DtFilterState();
		filterState.arraysFilter = arraysFilter.copy();
		filterState.enumsFilter = enumsFilter.copy();
		filterState.functionsFilter = functionsFilter.copy();
		filterState.structuresFilter = structuresFilter.copy();
		filterState.pointersFilter = pointersFilter.copy();
		filterState.unionsFilter = unionsFilter.copy();
		return filterState;
	}

	public boolean isShowArrays() {
		return arraysFilter.isTypeActive();
	}

	public DtTypeFilter getArraysFilter() {
		return arraysFilter;
	}

	public void setArraysFilter(DtTypeFilter filter) {
		this.arraysFilter = filter;
	}

	public boolean isShowEnums() {
		return enumsFilter.isTypeActive();
	}

	public DtTypeFilter getEnumsFilter() {
		return enumsFilter;
	}

	public void setEnumsFilter(DtTypeFilter filter) {
		this.enumsFilter = filter;
	}

	public boolean isShowFunctions() {
		return functionsFilter.isTypeActive();
	}

	public DtTypeFilter getFunctionsFilter() {
		return functionsFilter;
	}

	public void setFunctionsFilter(DtTypeFilter filter) {
		this.functionsFilter = filter;
	}

	public boolean isShowPointers() {
		return pointersFilter.isTypeActive();
	}

	public DtTypeFilter getPointersFilter() {
		return pointersFilter;
	}

	public void setPointersFilter(DtTypeFilter filter) {
		this.pointersFilter = filter;
	}

	public boolean isShowStructures() {
		return structuresFilter.isTypeActive();
	}

	public DtTypeFilter getStructuresFilter() {
		return structuresFilter;
	}

	public void setStructuresFilter(DtTypeFilter filter) {
		this.structuresFilter = filter;
	}

	public boolean isShowUnions() {
		return unionsFilter.isTypeActive();
	}

	public DtTypeFilter getUnionsFilter() {
		return unionsFilter;
	}

	public void setUnionsFilter(DtTypeFilter filter) {
		this.unionsFilter = filter;
	}

	public boolean passesFilters(DataType dt) {

		DataTypeManager dtm = dt.getDataTypeManager();
		if (dtm instanceof BuiltInDataTypeManager) {
			// never filter built-in types here; users can filter them using the text filter
			return true;
		}

		DataType baseDt = DataTypeUtils.getBaseDataType(dt);

		if (dt instanceof Array) {
			return passes(arraysFilter, dt);
		}

		if (dt instanceof Pointer) {
			return passes(pointersFilter, dt);
		}

		if (baseDt instanceof Enum) {
			return passes(enumsFilter, dt);
		}

		if (baseDt instanceof Function) {
			return passes(functionsFilter, dt);
		}

		if (baseDt instanceof Structure) {
			return passes(structuresFilter, dt);
		}

		if (baseDt instanceof Union) {
			return passes(unionsFilter, dt);
		}

		return true;
	}

	private boolean passes(DtTypeFilter filter, DataType dt) {
		if (dt instanceof TypeDef) {
			return filter.isTypeDefActive();
		}

		return filter.isTypeActive();
	}

	public void save(SaveState parentSaveState) {

		SaveState ss = new SaveState(XML_NAME);
		ss.putSaveState(arraysFilter.getName(), arraysFilter.save());
		ss.putSaveState(enumsFilter.getName(), enumsFilter.save());
		ss.putSaveState(functionsFilter.getName(), functionsFilter.save());
		ss.putSaveState(pointersFilter.getName(), pointersFilter.save());
		ss.putSaveState(structuresFilter.getName(), structuresFilter.save());
		ss.putSaveState(unionsFilter.getName(), unionsFilter.save());

		parentSaveState.putSaveState(XML_NAME, ss);
	}

	public void restore(SaveState parentSaveState) {

		SaveState ss = parentSaveState.getSaveState(XML_NAME);
		if (ss == null) {
			return;
		}

		arraysFilter = DtTypeFilter.restore("Arrays", ss.getSaveState("Arrays"));
		enumsFilter = DtTypeFilter.restore("Enums", ss.getSaveState("Enums"));
		functionsFilter = DtTypeFilter.restore("Functions", ss.getSaveState("Functions"));
		pointersFilter = DtTypeFilter.restore("Pointers", ss.getSaveState("Pointers"));
		structuresFilter = DtTypeFilter.restore("Structures", ss.getSaveState("Structures"));
		unionsFilter = DtTypeFilter.restore("Unions", ss.getSaveState("Unions"));
	}

	@Override
	public int hashCode() {
		return Objects.hash(arraysFilter, enumsFilter, functionsFilter, pointersFilter,
			structuresFilter, unionsFilter);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		DtFilterState other = (DtFilterState) obj;
		return Objects.equals(arraysFilter, other.arraysFilter) &&
			Objects.equals(enumsFilter, other.enumsFilter) &&
			Objects.equals(functionsFilter, other.functionsFilter) &&
			Objects.equals(pointersFilter, other.pointersFilter) &&
			Objects.equals(structuresFilter, other.structuresFilter) &&
			Objects.equals(unionsFilter, other.unionsFilter);
	}

}
