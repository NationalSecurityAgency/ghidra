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
package docking.theme.gui;

import java.awt.*;
import java.util.Comparator;
import java.util.List;
import java.util.function.Supplier;

import javax.swing.Icon;
import javax.swing.JLabel;

import docking.theme.*;
import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.WebColors;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

public class ThemeColorTableModel extends GDynamicColumnTableModel<ColorValue, Object> {
	private List<ColorValue> colors;
	private GThemeValueMap values;
	private GThemeValueMap coreDefaults;
	private GThemeValueMap darkDefaults;

	public ThemeColorTableModel() {
		super(new ServiceProviderStub());
		loadValues();
	}

	public void reload() {
		loadValues();
		fireTableDataChanged();
	}

	private void loadValues() {
		values = Gui.getAllValues();
		coreDefaults = Gui.getCoreDefaults();
		darkDefaults = Gui.getDarkDefaults();
		colors = values.getColors();
	}

	@Override
	public String getName() {
		return "Users";
	}

	@Override
	public List<ColorValue> getModelData() {
		return colors;
	}

	@Override
	protected TableColumnDescriptor<ColorValue> createTableColumnDescriptor() {
		TableColumnDescriptor<ColorValue> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new IdColumn());
		descriptor.addVisibleColumn(new ValueColumn("Current Color", () -> values));
		descriptor.addVisibleColumn(new ValueColumn("Core Defaults", () -> coreDefaults));
		descriptor.addVisibleColumn(new ValueColumn("Dark Defaults", () -> darkDefaults));
		descriptor.addVisibleColumn(new IsLafPropertyColumn());
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

		@Override
		public int getColumnPreferredWidth() {
			return 300;
		}
	}

	class ValueColumn extends AbstractDynamicTableColumn<ColorValue, ColorValue, Object> {
		private ThemeColorRenderer renderer;
		private String name;
		private Supplier<GThemeValueMap> valueSupplier;

		ValueColumn(String name, Supplier<GThemeValueMap> supplier) {
			this.name = name;
			this.valueSupplier = supplier;
			renderer = new ThemeColorRenderer(supplier);
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
			return (v1, v2) -> valueSupplier.get()
					.getColor(v1.getId())
					.compareValue(valueSupplier.get().getColor(v2.getId()));
		}

		@Override
		public int getColumnPreferredWidth() {
			return 300;
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

		@Override
		public int getColumnPreferredWidth() {
			return 20;
		}
	}

	private class ThemeColorRenderer extends AbstractGColumnRenderer<ColorValue> {

		private Supplier<GThemeValueMap> mapSupplier;

		public ThemeColorRenderer(Supplier<GThemeValueMap> mapSupplier) {
			this.mapSupplier = mapSupplier;
			setFont(new Font("Monospaced", Font.PLAIN, 12));
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			GThemeValueMap valueMap = mapSupplier.get();
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
			label.setIcon(new SwatchIcon(color, label.getForeground()));
//			label.setBackground(color);
//			label.setForeground(ColorUtils.contrastForegroundColor(color));
			label.setOpaque(true);
			return label;
		}

		@Override
		public String getFilterString(ColorValue t, Settings settings) {
			return t.getId();
		}

	}

	static class SwatchIcon implements Icon {
		private Color color;
		private Color border;

		SwatchIcon(Color c, Color border) {
			this.color = c;
			this.border = border;
		}

		@Override
		public void paintIcon(Component c, Graphics g, int x, int y) {
			g.setColor(color);
			g.fillRect(x, y, 25, 16);
			g.setColor(border);
			g.drawRect(x, y, 25, 16);
		}

		@Override
		public int getIconWidth() {
			return 25;
		}

		@Override
		public int getIconHeight() {
			return 16;
		}

	}
}
