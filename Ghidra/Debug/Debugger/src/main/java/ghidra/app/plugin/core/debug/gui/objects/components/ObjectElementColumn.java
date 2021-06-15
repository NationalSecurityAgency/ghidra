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
package ghidra.app.plugin.core.debug.gui.objects.components;

import java.util.Comparator;
import java.util.List;
import java.util.function.Function;

import ghidra.app.plugin.core.debug.gui.objects.components.ObjectEnumeratedColumnTableModel.ObjectsEnumeratedTableColumn;

public class ObjectElementColumn
		implements ObjectsEnumeratedTableColumn<ObjectElementColumn, ObjectElementRow> {

	private final String header;
	private final Function<ObjectElementRow, ?> getter;

	public ObjectElementColumn(String header, Function<ObjectElementRow, Object> getter) {
		this.header = header;
		this.getter = getter;
	}

	@Override
	public String getHeader() {
		return header;
	}

	@Override
	public Object getValueOf(ObjectElementRow row) {
		row.setCurrentKey(header);
		return getter.apply(row);
	}

	public static ObjectsEnumeratedTableColumn<ObjectElementColumn, ? super ObjectElementRow>[] generateColumns(
			List<String> keys) {
		keys.sort(Comparator.comparing(String::toString));
		ObjectElementColumn[] array = new ObjectElementColumn[keys.size()];
		int i = 0;
		for (String k : keys) {
			ObjectElementColumn col = new ObjectElementColumn(k, ObjectElementRow::getValue);
			array[i++] = col;
		}
		return array;
	}
}
