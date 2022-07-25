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
import ghidra.util.ColorUtils;
import ghidra.util.WebColors;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

public class ThemeColorTableModel extends GDynamicColumnTableModel<ColorValue, Object> {
	private List<ColorValue> colors;
	private GThemeValueMap currentValues;
	private GThemeValueMap themeValues;
	private GThemeValueMap defaultValues;
	private GThemeValueMap lightDefaultValues;
	private GThemeValueMap darkDefaultValues;

	public ThemeColorTableModel() {
		super(new ServiceProviderStub());
		load();
	}

	public void reloadCurrent() {
		currentValues = Gui.getAllValues();
		colors = currentValues.getColors();
		fireTableDataChanged();
	}

	public void reloadAll() {
		load();
		fireTableDataChanged();
	}

	private void load() {
		currentValues = Gui.getAllValues();
		colors = currentValues.getColors();
		themeValues = new GThemeValueMap(currentValues);
		defaultValues = Gui.getDefaults();
		lightDefaultValues = Gui.getGhidraLightDefaults();
		darkDefaultValues = Gui.getGhidraDarkDefaults();

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
		descriptor.addVisibleColumn(new ValueColumn("Current Color", () -> currentValues));
		descriptor.addVisibleColumn(new ValueColumn("Theme Color", () -> themeValues));
		descriptor.addVisibleColumn(new ValueColumn("Default Color", () -> defaultValues));
		descriptor.addHiddenColumn(new ValueColumn("Light Defaults", () -> lightDefaultValues));
		descriptor.addHiddenColumn(new ValueColumn("Dark Defaults", () -> darkDefaultValues));
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

	class ValueColumn extends AbstractDynamicTableColumn<ColorValue, ResolvedColor, Object> {
		private ThemeColorRenderer renderer;
		private String name;
		private Supplier<GThemeValueMap> valueSupplier;

		ValueColumn(String name, Supplier<GThemeValueMap> supplier) {
			this.name = name;
			this.valueSupplier = supplier;
			renderer = new ThemeColorRenderer();
		}

		@Override
		public String getColumnName() {
			return name;
		}

		@Override
		public ResolvedColor getValue(ColorValue themeColor, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {
			GThemeValueMap valueMap = valueSupplier.get();
			String id = themeColor.getId();
			ColorValue colorValue = valueMap.getColor(id);
			if (colorValue == null) {
				return null;
			}
			Color color = colorValue.get(valueMap);
			return new ResolvedColor(id, colorValue.getReferenceId(), color);
		}

		@Override
		public GColumnRenderer<ResolvedColor> getColumnRenderer() {
			return renderer;
		}

		public Comparator<ResolvedColor> getComparator() {
			return (v1, v2) -> {
				if (v1 == null && v2 == null) {
					return 0;
				}
				if (v1 == null) {
					return 1;
				}
				if (v2 == null) {
					return -1;
				}
				return ColorUtils.COMPARATOR.compare(v1.color, v2.color);
			};
		}

		@Override
		public int getColumnPreferredWidth() {
			return 300;
		}

	}

	private class ThemeColorRenderer extends AbstractGColumnRenderer<ResolvedColor> {

		public ThemeColorRenderer() {
			setFont(new Font("Monospaced", Font.PLAIN, 12));
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			JLabel label = (JLabel) super.getTableCellRendererComponent(data);
			ResolvedColor resolved = (ResolvedColor) data.getValue();

			String text = getValueText(resolved);
			Color color = resolved == null ? GThemeDefaults.Colors.BACKGROUND : resolved.color;
			label.setText(text);
			label.setIcon(new SwatchIcon(color, label.getForeground()));
			label.setOpaque(true);
			return label;
		}

		private String getValueText(ResolvedColor resolvedColor) {
			if (resolvedColor == null) {
				return "<No Value>";
			}
			if (resolvedColor.refId != null) {
				return resolvedColor.refId;
			}
			Color color = resolvedColor.color;
			String text = WebColors.toString(color, false);
			String name = WebColors.toWebColorName(color);
			if (name != null) {
				text += " [" + name + "]";
			}
			return text;
		}

		@Override
		public String getFilterString(ResolvedColor colorValue, Settings settings) {
			return getValueText(colorValue);
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

	class ResolvedColor {
		String id;
		String refId;
		Color color;

		ResolvedColor(String id, String refId, Color color) {
			this.id = id;
			this.refId = refId;
			this.color = color;
		}
	}
}
