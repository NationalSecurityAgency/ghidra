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

import java.awt.Component;
import java.awt.Font;
import java.util.Comparator;
import java.util.List;
import java.util.function.Supplier;

import javax.swing.JLabel;

import docking.theme.*;
import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

public class ThemeFontTableModel extends GDynamicColumnTableModel<FontValue, Object> {
	private List<FontValue> fonts;
	private GThemeValueMap currentValues;
	private GThemeValueMap themeValues;
	private GThemeValueMap defaultValues;

	public ThemeFontTableModel() {
		super(new ServiceProviderStub());
		load();
	}

	private void load() {
		currentValues = Gui.getAllValues();
		fonts = currentValues.getFonts();
		themeValues = new GThemeValueMap(currentValues);
		defaultValues = Gui.getDefaults();
	}

	@Override
	public String getName() {
		return "Fonts";
	}

	@Override
	public List<FontValue> getModelData() {
		return fonts;
	}

	@Override
	protected TableColumnDescriptor<FontValue> createTableColumnDescriptor() {
		TableColumnDescriptor<FontValue> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new IdColumn());
		descriptor.addVisibleColumn(new FontValueColumn("Current Font", () -> currentValues));
		descriptor.addVisibleColumn(new FontValueColumn("Theme Font", () -> themeValues));
		descriptor.addVisibleColumn(new FontValueColumn("Default Font", () -> defaultValues));
		return descriptor;
	}

	@Override
	public Object getDataSource() {
		return null;
	}

	class IdColumn extends AbstractDynamicTableColumn<FontValue, String, Object> {

		@Override
		public String getColumnName() {
			return "Id";
		}

		@Override
		public String getValue(FontValue fontValue, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {
			return fontValue.getId();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 300;
		}
	}

	class FontValueColumn extends AbstractDynamicTableColumn<FontValue, ResolvedFont, Object> {
		private ThemeFontRenderer renderer;
		private String name;
		private Supplier<GThemeValueMap> valueSupplier;

		FontValueColumn(String name, Supplier<GThemeValueMap> supplier) {
			this.name = name;
			this.valueSupplier = supplier;
			renderer = new ThemeFontRenderer();
		}

		@Override
		public String getColumnName() {
			return name;
		}

		@Override
		public ResolvedFont getValue(FontValue fontValue, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {
			GThemeValueMap valueMap = valueSupplier.get();
			String id = fontValue.getId();
			FontValue value = valueMap.getFont(id);
			if (value == null) {
				return null;
			}
			Font font = value.get(valueMap);
			return new ResolvedFont(id, value.getReferenceId(), font);
		}

		@Override
		public GColumnRenderer<ResolvedFont> getColumnRenderer() {
			return renderer;
		}

		public Comparator<ResolvedFont> getComparator() {
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
				return v1.font().toString().compareTo(v2.font().toString());
			};
		}

		@Override
		public int getColumnPreferredWidth() {
			return 300;
		}

	}

	private class ThemeFontRenderer extends AbstractGColumnRenderer<ResolvedFont> {

		public ThemeFontRenderer() {
			setFont(new Font("Monospaced", Font.PLAIN, 12));
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			JLabel label = (JLabel) super.getTableCellRendererComponent(data);
			ResolvedFont resolved = (ResolvedFont) data.getValue();

			String text = getValueText(resolved);
			label.setText(text);
			label.setOpaque(true);
			return label;
		}

		private String getValueText(ResolvedFont resolvedFont) {
			if (resolvedFont == null) {
				return "<No Value>";
			}
			Font font = resolvedFont.font();
			String fontString = FileGTheme.fontToString(font);

			if (resolvedFont.refId() != null) {
				return resolvedFont.refId() + "  [" + fontString + "]";
			}
			return fontString;
		}

		@Override
		public String getFilterString(ResolvedFont fontValue, Settings settings) {
			return getValueText(fontValue);
		}

	}

	record ResolvedFont(String id, String refId, Font font) {/**/}

	public void reloadCurrent() {

		currentValues = Gui.getAllValues();
		fonts = currentValues.getFonts();
		fireTableDataChanged();

	}

	public void reloadAll() {
		load();
		fireTableDataChanged();
	}

}
