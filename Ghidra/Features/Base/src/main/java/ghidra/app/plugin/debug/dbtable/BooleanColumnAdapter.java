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
package ghidra.app.plugin.debug.dbtable;

import db.BooleanField;
import db.DBRecord;
import docking.widgets.table.GBooleanCellRenderer;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.GColumnRenderer;

public class BooleanColumnAdapter extends AbstractColumnAdapter {

	private BooleanRenderer renderer = new BooleanRenderer();

	BooleanColumnAdapter(String columnName, int column) {
		super(columnName, column);
	}

	@Override
	public int getColumnPreferredWidth() {
		return 75;
	}

	@Override
	Class<?> getValueClass() {
		return Boolean.class;
	}

	@Override
	Object getKeyValue(DBRecord rec) {
		return Boolean.valueOf(((BooleanField) rec.getKeyField()).getBooleanValue());
	}

	@Override
	Object getValue(DBRecord rec, int dbColumn) {
		return Boolean.valueOf(rec.getBooleanValue(dbColumn));
	}

	@Override
	public BooleanRenderer getColumnRenderer() {
		return renderer;
	}

	private class BooleanRenderer extends GBooleanCellRenderer implements GColumnRenderer<Object> {
		@Override
		public String getFilterString(Object t, Settings settings) {
			Boolean b = (Boolean) t;
			if (b == null) {
				return Boolean.FALSE.toString();
			}
			return b.toString();
		}
	}
}
