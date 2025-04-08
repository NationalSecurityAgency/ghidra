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
package ghidra.app.plugin.core.function.editor;

import java.util.ArrayList;
import java.util.List;

import javax.swing.ListCellRenderer;

import docking.widgets.DropDownSelectionTextField;
import docking.widgets.DropDownTextFieldDataModel;
import docking.widgets.list.GListCellRenderer;
import ghidra.program.model.lang.Register;

/**
 * The data model for {@link DropDownSelectionTextField} that allows the text field to work with
 * {@link Register}s.
 */
public class RegisterDropDownSelectionDataModel implements DropDownTextFieldDataModel<Register> {

	private List<Register> registers;

	public RegisterDropDownSelectionDataModel(List<Register> registers) {
		this.registers = registers;
	}

	@Override
	public ListCellRenderer<Register> getListRenderer() {
		return new GListCellRenderer<Register>();
	}

	@Override
	public String getDescription(Register value) {
		return null;
	}

	@Override
	public String getDisplayText(Register value) {
		return value.getName();
	}

	@Override
	public List<Register> getMatchingData(String searchText) {

		if (searchText == null || searchText.length() == 0) {
			return registers;
		}

		searchText = searchText.toLowerCase();

		List<Register> regList = new ArrayList<>();
		for (Register reg : registers) {
			String regName = reg.getName().toLowerCase();
			if (regName.startsWith(searchText)) {
				regList.add(reg);
			}
		}
		return regList;
	}

	@Override
	public int getIndexOfFirstMatchingEntry(List<Register> data, String searchText) {

		String lcSearchText = searchText.toLowerCase();
		int len = data.size();
		for (int i = 0; i < len; i++) {
			String name = data.get(i).getName();
			String lcName = name.toLowerCase();
			if (lcName.startsWith(lcSearchText)) {
				return i;
			}
		}
		return 0;
	}

}
