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
package ghidra.app.plugin.runtimeinfo;

import java.awt.BorderLayout;
import java.util.*;

import javax.swing.JPanel;

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.Disposable;

/**
 * A {@link JPanel} that displays a 2-column table created from a {@link Map}
 *
 * @param <K> The {@link Map} key type
 * @param <V> The {@link Map} value type
 */
class MapTablePanel<K, V> extends JPanel implements Disposable {

	private String name;
	private Map<K, V> map;
	private String keyColumnName;
	private String valueColumnName;
	private int keyColumnWidth;
	private boolean showValueColumn;
	private Plugin plugin;
	private GFilterTable<Map.Entry<K, V>> table;

	/**
	 * Creates a new {@link MapTablePanel}
	 * 
	 * @param name The name of the panel
	 * @param map The {@link Map}
	 * @param keyColumnName The name of the key column
	 * @param valueName The name of the value column
	 * @param keyColumnWidth The width of the key column, in pixels
	 * @param showValueColumn True if the value column should be visible; false if it should be
	 *   hidden
	 * @param plugin The {@link Plugin} associated with this {@link MapTablePanel}
	 */
	MapTablePanel(String name, Map<K, V> map, String keyColumnName, String valueName,
			int keyColumnWidth, boolean showValueColumn, Plugin plugin) {
		this.name = name;
		this.map = map;
		this.keyColumnName = keyColumnName;
		this.valueColumnName = valueName;
		this.keyColumnWidth = keyColumnWidth;
		this.showValueColumn = showValueColumn;
		this.plugin = plugin;
		this.table = new GFilterTable<>(new MapModel());

		setLayout(new BorderLayout());
		add(table, BorderLayout.CENTER);
	}

	@Override
	public void dispose() {
		table.dispose();
	}

	private class MapModel
			extends GDynamicColumnTableModel<Map.Entry<K, V>, List<Map.Entry<K, V>>> {

		private List<Map.Entry<K, V>> entries;

		public MapModel() {
			super(plugin.getTool());
			entries = new ArrayList<>(map.entrySet());
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public List<Map.Entry<K, V>> getModelData() {
			return entries;
		}

		@Override
		protected TableColumnDescriptor<Map.Entry<K, V>> createTableColumnDescriptor() {
			TableColumnDescriptor<Map.Entry<K, V>> columnDescriptor = new TableColumnDescriptor<>();
			columnDescriptor.addVisibleColumn(new KeyColumn());
			if (showValueColumn) {
				columnDescriptor.addVisibleColumn(new ValueColumn());
			}
			else {
				columnDescriptor.addHiddenColumn(new ValueColumn());
			}
			return columnDescriptor;
		}

		@Override
		public List<Map.Entry<K, V>> getDataSource() {
			return entries;
		}

		private class KeyColumn
				extends AbstractDynamicTableColumn<Map.Entry<K, V>, K, List<Map.Entry<K, V>>> {

			@Override
			public String getColumnName() {
				return keyColumnName;
			}

			@Override
			public K getValue(Map.Entry<K, V> entry, Settings settings, List<Map.Entry<K, V>> data,
					ServiceProvider services) throws IllegalArgumentException {
				return entry.getKey();
			}

			@Override
			public int getColumnPreferredWidth() {
				return keyColumnWidth;
			}
		}

		private class ValueColumn
				extends AbstractDynamicTableColumn<Map.Entry<K, V>, V, List<Map.Entry<K, V>>> {

			@Override
			public String getColumnName() {
				return valueColumnName;
			}

			@Override
			public V getValue(Map.Entry<K, V> entry, Settings settings, List<Map.Entry<K, V>> data,
					ServiceProvider services) throws IllegalArgumentException {
				return entry.getValue();
			}
		}
	}
}
