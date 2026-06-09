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
package ghidra.app.plugin.core.decompiler.taint;

import java.util.*;

import docking.widgets.table.ObjectSelectedListener;
import ghidra.app.plugin.core.decompiler.taint.TaintState.MarkType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.Msg;

/**
 * The data that populates the TaintHighlight table. This data is all the active and inactive taint labels.
 * The following items should be editable:
 * <ul><li>
 * Whether the taint label is active or inactive.
 * </li><li>
 * The "label" associated with the source, sink, or gate.
 * </li></ul>
 */
public class TaintLabelsDataFrame implements ObjectSelectedListener<Map<String, Object>> {

	private List<String> columns;

	// Each item in the list is a row, the rows are maps from column names -> data.
	// NOTE: These results need to transfer back to the TaintState.
	public List<Map<String, Object>> tableResults;

	private TaintPlugin plugin;

	/**
	 * Sarif Data is associated with a plugin and a program.
	 * 
	 * @param plugin - plugin
	 */
	public TaintLabelsDataFrame(TaintPlugin plugin) {

		this.plugin = plugin;

		columns = new ArrayList<>();
		tableResults = new ArrayList<>();

		columns.add("Selected");
		columns.add("Address");
		columns.add("Label");
		columns.add("Name");
		columns.add("Category");
		columns.add("Function Address");
		columns.add("Taint Label Object");

		Msg.info(this, "Created TaintLabelsDataFrame");
	}

	public List<String> getColumnHeaders() {
		return columns;
	}

	public void loadData() {
		tableResults = new ArrayList<>();
		Msg.info(this, "Loading TaintLabelsDataFrame");

		for (MarkType category : new MarkType[] { MarkType.SOURCE, MarkType.SINK, MarkType.GATE }) {

			// loading data from TaintState which should be the start state of this table.
			for (TaintLabel taint_label : plugin.getTaintState().getTaintLabels(category)) {

				Map<String, Object> row = new HashMap<>();
				HighVariable hv = taint_label.getHighVariable();

				if (hv == null) {
					row.put("Name", taint_label.getFunctionName());
					row.put("Function Address", null);
					row.put("Address", null);
				}
				else {
					row.put("Name", hv.getName());
					row.put("Function Address", hv.getHighFunction().getFunction().getEntryPoint());
					Address addr = hv.getSymbol() == null ? null : hv.getSymbol().getPCAddress();
					row.put("Address", addr);
				}

				row.put("Label", taint_label.getLabel());
				row.put("Taint Label Object", taint_label);
				row.put("Category", category);
				row.put("Selected", taint_label.isActive());

				Msg.info(this, "Row loaded: " + taint_label.toString());
				tableResults.add(row);
			}
		}
	}

	public void setSelected(int row, Boolean value) {
		Map<String, Object> row_data = tableResults.get(row);
		row_data.put("Selected", value);
	}

	public void toggleSelected(int row) {
		Map<String, Object> rowData = tableResults.get(row);
		Boolean status = (Boolean) rowData.get("Selected");
		rowData.put("Selected", !status);
	}

	public void setLabel(int row, String label) {
		tableResults.get(row).put("Label", label);
		Msg.info(this, "New label value: " + tableResults.get(row).get("Label"));
	}

	public AddressSet getTaintAddressSet() {
		AddressSet aset = new AddressSet();

		if (tableResults != null && tableResults.size() > 0) {
			for (Map<String, Object> map : tableResults) {
				aset.add((Address) map.get("Address"));
			}
		}
		return aset;
	}

	public void dumpTableToDebug() {
		for (Map<String, Object> row : tableResults) {
			StringBuilder sb = new StringBuilder();
			for (Map.Entry<String, Object> entry : row.entrySet()) {
				sb.append(String.format("(%s,%s), ", entry.getKey(), entry.getValue()));
			}
			Msg.info(this, sb.toString());
		}
	}

	/**
	 * @param row This is ALL the data in the row we can use.
	 */
	@Override
	public void objectSelected(Map<String, Object> row) {
		if (row != null && row.containsKey("Address")) {
			List<Address> addr_list = new ArrayList<Address>();
			addr_list.add((Address) row.get("Address"));
			Msg.info(this, "Making selection, " + row.get("Address"));
			this.plugin.makeSelection(addr_list);
		}
	}

	public List<Map<String, Object>> getData() {
		return this.tableResults;
	}
}
