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
import java.util.*;
import java.util.function.Supplier;

import javax.swing.*;

import docking.widgets.table.*;
import generic.theme.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import resources.icons.*;

/**
 * Table model for theme icons
 */
public class ThemeIconTableModel extends GDynamicColumnTableModel<IconValue, Object> {
	private List<IconValue> icons;
	private GThemeValueMap currentValues;
	private GThemeValueMap themeValues;
	private GThemeValueMap defaultValues;
	private GThemeValuesCache valuesProvider;
	private boolean showSystemValues;

	public ThemeIconTableModel(GThemeValuesCache valuesProvider) {
		super(new ServiceProviderStub());
		this.valuesProvider = valuesProvider;
		load();
	}

	public void setShowSystemValues(boolean show) {
		this.showSystemValues = show;
	}

	public boolean isShowingSystemValues() {
		return showSystemValues;
	}

	protected void filter() {

		List<IconValue> filtered = new ArrayList<>();

		for (IconValue iconValue : icons) {
			String id = iconValue.getId();
			if (showSystemValues) {
				filtered.add(iconValue);
				continue;
			}

			if (!Gui.isSystemId(id)) {
				filtered.add(iconValue);
			}

		}

		icons = filtered;
	}

	/**
	 * Reloads the just the current values shown in the table. Called whenever an icon changes.
	 */
	public void reloadCurrent() {
		currentValues = valuesProvider.getCurrentValues();
		icons = currentValues.getIcons();
		fireTableDataChanged();
	}

	/**
	 * Reloads all the current values and all the default values in the table. Called when the
	 * theme changes or the application defaults have been forced to reload.
	 */
	public void reloadAll() {
		load();
		fireTableDataChanged();
	}

	private void load() {
		currentValues = valuesProvider.getCurrentValues();
		icons = currentValues.getIcons();
		themeValues = valuesProvider.getThemeValues();
		defaultValues = valuesProvider.getDefaultValues();

		filter();
	}

	@Override
	public String getName() {
		return "Fonts";
	}

	@Override
	public List<IconValue> getModelData() {
		return icons;
	}

	@Override
	protected TableColumnDescriptor<IconValue> createTableColumnDescriptor() {
		TableColumnDescriptor<IconValue> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new IdColumn());
		descriptor.addVisibleColumn(new IconValueColumn("Current Icon", () -> currentValues));
		descriptor.addVisibleColumn(new IconValueColumn("Theme Icon", () -> themeValues));
		descriptor.addVisibleColumn(new IconValueColumn("Default Icon", () -> defaultValues));
		return descriptor;
	}

	@Override
	public Object getDataSource() {
		return null;
	}

	/**
	 * Returns the original value for the id as defined by the current theme
	 * @param id the resource id to get a font value for
	 * @return  the original value for the id as defined by the current theme
	 */
	public IconValue getThemeValue(String id) {
		return themeValues.getIcon(id);
	}

	private class IdColumn extends AbstractDynamicTableColumn<IconValue, String, Object> {

		@Override
		public String getColumnName() {
			return "Id";
		}

		@Override
		public String getValue(IconValue iconValue, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {
			return iconValue.getId();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 300;
		}
	}

	private class IconValueColumn
			extends AbstractDynamicTableColumn<IconValue, ResolvedIcon, Object> {
		private ThemeIconRenderer renderer;
		private String name;
		private Supplier<GThemeValueMap> valueSupplier;

		IconValueColumn(String name, Supplier<GThemeValueMap> supplier) {
			this.name = name;
			this.valueSupplier = supplier;
			renderer = new ThemeIconRenderer();
		}

		@Override
		public String getColumnName() {
			return name;
		}

		@Override
		public ResolvedIcon getValue(IconValue iconValue, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {
			GThemeValueMap valueMap = valueSupplier.get();
			String id = iconValue.getId();
			IconValue value = valueMap.getIcon(id);
			if (value == null) {
				return null;
			}
			Icon icon = value.get(valueMap);
			return new ResolvedIcon(id, value.getReferenceId(), icon);
		}

		@Override
		public GColumnRenderer<ResolvedIcon> getColumnRenderer() {
			return renderer;
		}

		@Override
		public Comparator<ResolvedIcon> getComparator() {
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
				return v1.icon().toString().compareTo(v2.icon().toString());
			};
		}

		@Override
		public int getColumnPreferredWidth() {
			return 300;
		}

	}

	private class ThemeIconRenderer extends AbstractGColumnRenderer<ResolvedIcon> {

		public ThemeIconRenderer() {
			setFont(Gui.getFont("font.monospaced"));
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			Component comp = super.getTableCellRendererComponent(data);
			JLabel label = (JLabel) comp;
			ResolvedIcon resolved = (ResolvedIcon) data.getValue();

			String text = getValueText(resolved);
			Icon icon = prepareIcon(resolved.icon());
			label.setIcon(icon);
			label.setText(text);
			label.setOpaque(true);
			return label;
		}

		private Icon prepareIcon(Icon icon) {
			if (!(icon instanceof LazyImageIcon)) {
				icon = new ProtectedIcon(icon);
			}
			if (icon.getIconWidth() != 16 && icon.getIconHeight() != 16) {
				icon = new ScaledImageIcon(icon, 16, 16);
			}
			return icon;
		}

		private String getValueText(ResolvedIcon resolvedIcon) {
			if (resolvedIcon == null) {
				return "<No Value>";
			}
			Icon icon = resolvedIcon.icon();
			String sizeString = "[" + icon.getIconWidth() + "x" + icon.getIconHeight() + "] ";

			String iconString = GTheme.JAVA_ICON;
			if (icon instanceof UrlImageIcon urlIcon) {
				iconString = urlIcon.getOriginalPath();
			}
			else if (icon instanceof ImageIcon imageIcon) {
				String description = imageIcon.getDescription();
				if (description != null) {
					iconString = "[" + description + "]";
				}
			}
			if (resolvedIcon.refId() != null) {
				iconString = resolvedIcon.refId() + "  [" + iconString + "]";
			}
			return String.format("%-8s%s", sizeString, iconString);
		}

		@Override
		public String getFilterString(ResolvedIcon iconValue, Settings settings) {
			return getValueText(iconValue);
		}
	}

	private record ResolvedIcon(String id, String refId, Icon icon) {
		/**/}
}
