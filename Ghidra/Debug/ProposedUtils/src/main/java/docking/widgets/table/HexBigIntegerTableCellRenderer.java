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
package docking.widgets.table;

import java.awt.Component;
import java.math.BigInteger;

import javax.swing.JTable;
import javax.swing.table.TableModel;

import ghidra.docking.settings.Settings;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class HexBigIntegerTableCellRenderer extends AbstractGColumnRenderer<BigInteger> {
	@Override
	protected void configureFont(JTable table, TableModel model, int column) {
		setFont(fixedWidthFont);
	}

	protected String formatBigInteger(BigInteger value) {
		return value == null ? "??" : value.toString(16);
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {
		super.getTableCellRendererComponent(data);
		setText(formatBigInteger((BigInteger) data.getValue()));
		return this;
	}

	// TODO: Seems the filter model does not heed this....
	@Override
	public String getFilterString(BigInteger t, Settings settings) {
		return formatBigInteger(t);
	}
}
