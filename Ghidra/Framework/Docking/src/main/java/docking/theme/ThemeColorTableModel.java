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
package docking.theme;

import java.awt.*;
import java.util.Comparator;
import java.util.List;

import javax.swing.JLabel;

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.ColorUtils;
import ghidra.util.WebColors;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

public class ThemeColorTableModel extends GDynamicColumnTableModel<ColorValue, Object> {
	private List<ColorValue> colors;

	public ThemeColorTableModel(GTheme theme) {
		super(new ServiceProviderStub());
		colors = Gui.getAllValues().getColors();
	}

	public void refresh() {
		colors = Gui.getAllValues().getColors();
		fireTableDataChanged();
	}

	@Override
	public String getName() {
		return "Users";
	}

	@Override
	public List<ColorValue> getModelData() {
		return colors;
	}

	public boolean isCellEditable(int row, int column) {
		return getColumnName(column).equals("Current Color");
	}

	@Override
	protected TableColumnDescriptor<ColorValue> createTableColumnDescriptor() {
		TableColumnDescriptor<ColorValue> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new IdColumn());
		descriptor.addVisibleColumn(new IsLafPropertyColumn());
		descriptor.addVisibleColumn(new ValueColumn("Current Color", Gui.getAllValues()));
		descriptor.addVisibleColumn(new ValueColumn("Core Defaults", Gui.getAllValues()));
		descriptor.addVisibleColumn(new ValueColumn("Dark Defaults", Gui.getDarkDefaults()));
		return descriptor;
	}

	@Override
	public Object getDataSource() {
		return null;
	}

	class IdColumn extends AbstractDynamicTableColumn<ColorValue, String, Object> {

		@Override
		public String getColumnName() {
			return "Id";
		}

		@Override
		public String getValue(ColorValue themeColor, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {
			return themeColor.getId();
		}
	}

	class ValueColumn extends AbstractDynamicTableColumn<ColorValue, ColorValue, Object> {
		private ThemeColorRenderer renderer = new ThemeColorRenderer(Gui.getAllValues());
		private GThemeValueMap valueMap;
		private String name;

		ValueColumn(String name, GThemeValueMap valueMap) {
			this.name = name;
			this.valueMap = valueMap;
			renderer = new ThemeColorRenderer(valueMap);
		}

		@Override
		public String getColumnName() {
			return name;
		}

		@Override
		public ColorValue getValue(ColorValue themeColor, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {
			return themeColor;
		}

		@Override
		public GColumnRenderer<ColorValue> getColumnRenderer() {
			return renderer;
		}

		public Comparator<ColorValue> getComparator() {
			return (v1, v2) -> valueMap.getColor(v1.getId())
					.compareValue(valueMap.getColor(v2.getId()));
		}

	}

	class IsLafPropertyColumn extends AbstractDynamicTableColumn<ColorValue, Boolean, Object> {

		@Override
		public String getColumnName() {
			return "Is Laf";
		}

		@Override
		public Boolean getValue(ColorValue themeColor, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {
			return Gui.isJavaDefinedColor(themeColor.getId());
		}
	}

	private class ThemeColorRenderer extends AbstractGColumnRenderer<ColorValue> {

		private GThemeValueMap valueMap;

		public ThemeColorRenderer(GThemeValueMap valueMap) {
			this.valueMap = valueMap;
			setFont(new Font("Monospaced", Font.PLAIN, 12));
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel label = (JLabel) super.getTableCellRendererComponent(data);
			String id = ((ColorValue) data.getValue()).getId();

			ColorValue colorValue = valueMap.getColor(id);
			Color color;
			String text;
			if (colorValue != null) {
				color = colorValue.get(valueMap);
				if (colorValue.getReferenceId() != null) {
					text = colorValue.getReferenceId();
				}
				else {
					text = WebColors.toString(color, false);
					String name = WebColors.toWebColorName(color);
					if (name != null) {
						text += " [" + name + "]";
					}
				}

			}
			else {
				color = GThemeDefaults.Colors.BACKGROUND;
				text = "<No Value>";
			}
			label.setText(text);
			label.setBackground(color);
			label.setForeground(ColorUtils.contrastForegroundColor(color));
			label.setOpaque(true);
			return label;
		}

		@Override
		public String getFilterString(ColorValue t, Settings settings) {
			return t.getId();
		}

	}
}
