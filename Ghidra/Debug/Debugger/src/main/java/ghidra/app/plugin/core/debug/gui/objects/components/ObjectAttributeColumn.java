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

import java.util.function.Function;

import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;

public enum ObjectAttributeColumn
	implements EnumeratedTableColumn<ObjectAttributeColumn, ObjectAttributeRow> {
	NAME("Name", String.class, ObjectAttributeRow::getName),
	KIND("Kind", String.class, ObjectAttributeRow::getKind),
	VALUE("Value", String.class, ObjectAttributeRow::getValue),
	TYPE("Type", String.class, ObjectAttributeRow::getType);

	private final String header;
	private final Function<ObjectAttributeRow, ?> getter;
	private final Class<?> cls;

	<T> ObjectAttributeColumn(String header, Class<T> cls, Function<ObjectAttributeRow, T> getter) {
		this.header = header;
		this.cls = cls;
		this.getter = getter;
	}

	@Override
	public String getHeader() {
		return header;
	}

	@Override
	public Class<?> getValueClass() {
		return cls;
	}

	@Override
	public Object getValueOf(ObjectAttributeRow row) {
		return getter.apply(row);
	}
}
