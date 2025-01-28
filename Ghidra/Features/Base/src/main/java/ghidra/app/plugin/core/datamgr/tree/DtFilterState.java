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

import ghidra.framework.options.SaveState;

/**
 * A simple object to store various filter settings for the data type provider.
 */
public class DtFilterState {

	private static final String XML_NAME = "DATA_TYPES_FILTER";

	private boolean showArrays = false;
	private boolean showEnums = true;
	private boolean showFunctions = true;
	private boolean showStructures = true;
	private boolean showTypedefs = true;
	private boolean showPointers = false;
	private boolean showUnions = true;

	public DtFilterState copy() {
		DtFilterState filterState = new DtFilterState();
		filterState.setShowArrays(showArrays);
		filterState.setShowEnums(showEnums);
		filterState.setShowFunctions(showFunctions);
		filterState.setShowStructures(showStructures);
		filterState.setShowTypedefs(showTypedefs);
		filterState.setShowPointers(showPointers);
		filterState.setShowUnions(showUnions);
		return filterState;
	}

	public boolean isShowPointers() {
		return showPointers;
	}

	public void setShowPointers(boolean showPointers) {
		this.showPointers = showPointers;
	}

	public boolean isShowStructures() {
		return showStructures;
	}

	public void setShowStructures(boolean showStructures) {
		this.showStructures = showStructures;
	}

	public boolean isShowTypedefs() {
		return showStructures;
	}

	public void setShowTypedefs(boolean showTypedefs) {
		this.showTypedefs = showTypedefs;
	}

	public boolean isShowEnums() {
		return showEnums;
	}

	public void setShowEnums(boolean showEnums) {
		this.showEnums = showEnums;
	}

	public boolean isShowFunctions() {
		return showFunctions;
	}

	public void setShowFunctions(boolean showFunctions) {
		this.showFunctions = showFunctions;
	}

	public boolean isShowUnions() {
		return showUnions;
	}

	public void setShowUnions(boolean showUnions) {
		this.showUnions = showUnions;
	}

	public boolean isShowArrays() {
		return showArrays;
	}

	public void setShowArrays(boolean showArrays) {
		this.showArrays = showArrays;
	}

	public void setshowPointers(boolean showPointers) {
		this.showPointers = showPointers;
	}

	public void save(SaveState parentSaveState) {

		SaveState saveState = new SaveState(XML_NAME);
		saveState.putBoolean("SHOW_ARRAYS", showArrays);
		saveState.putBoolean("SHOW_ENUMS", showEnums);
		saveState.putBoolean("SHOW_FUNCTIONS", showFunctions);
		saveState.putBoolean("SHOW_POINTERS", showPointers);
		saveState.putBoolean("SHOW_STRUCTURES", showStructures);
		saveState.putBoolean("SHOW_TYPEDEFS", showTypedefs);
		saveState.putBoolean("SHOW_UNIONS", showUnions);

		parentSaveState.putSaveState(XML_NAME, saveState);
	}

	public void restore(SaveState parentSaveState) {

		parentSaveState.getSaveState(XML_NAME);
		SaveState saveState = new SaveState();

		showArrays = saveState.getBoolean("SHOW_ARRAYS", false);
		showEnums = saveState.getBoolean("SHOW_ENUMS", true);
		showFunctions = saveState.getBoolean("SHOW_FUNCTIONS", true);
		showPointers = saveState.getBoolean("SHOW_POINTERS", false);
		showStructures = saveState.getBoolean("SHOW_STRUCTURES", true);
		showTypedefs = saveState.getBoolean("SHOW_TYPEDEFS", true);
		showUnions = saveState.getBoolean("SHOW_UNIONS", true);
	}

	@Override
	public int hashCode() {
		return Objects.hash(showArrays, showEnums, showFunctions, showPointers, showStructures,
			showTypedefs, showUnions);
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
		return showArrays == other.showArrays && showEnums == other.showEnums &&
			showFunctions == other.showFunctions && showPointers == other.showPointers &&
			showStructures == other.showStructures && showTypedefs == other.showTypedefs &&
			showUnions == other.showUnions;
	}

}
