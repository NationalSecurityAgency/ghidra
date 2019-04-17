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
package ghidra.feature.vt.gui.util;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JComponent;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.app.util.SymbolInspector;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.table.GhidraTableCellRenderer;

public class VTSymbolRenderer extends GhidraTableCellRenderer {

	private SymbolInspector inspector;

	public VTSymbolRenderer(ServiceProvider serviceProvider, JComponent repaintComponent) {
		inspector = new SymbolInspector(serviceProvider, repaintComponent);
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		super.getTableCellRendererComponent(data);

		Object value = data.getValue();
		boolean isSelected = data.isSelected();

		handleSymbol(value, isSelected);
		return this;
	}

	private void handleSymbol(Object value, boolean isSelected) {
		setBold();
		if (!isSelected) {
			Color color = Color.BLACK;
			if (value instanceof Symbol) {
				Symbol s = (Symbol) value;
				inspector.setProgram(s.getProgram());
				color = inspector.getColor(s);
			}
			setForeground(color);
		}
	}
}
