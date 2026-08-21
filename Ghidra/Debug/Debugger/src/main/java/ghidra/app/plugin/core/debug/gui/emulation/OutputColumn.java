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
package ghidra.app.plugin.core.debug.gui.emulation;

import java.util.function.BiConsumer;
import java.util.function.Function;

import javax.swing.table.TableCellEditor;

import docking.widgets.table.CustomToStringCellRenderer;
import docking.widgets.table.EnumeratedTableColumn;
import ghidra.program.model.data.DataType;
import ghidra.util.table.column.GColumnRenderer;

enum OutputColumn implements EnumeratedTableColumn<OutputColumn, OutputRow> {
	NAME("Name", String.class, OutputRow::getName),
	STORAGE("Storage", VarStorage.class, OutputRow::getStorage),
	VALUE("Value", String.class, OutputRow::getValueStr) {
		@Override
		public GColumnRenderer<?> getRenderer() {
			return CustomToStringCellRenderer.MONO_OBJECT;
		}
	},
	TYPE("Type", DataType.class, OutputRow::getType, OutputRow::setType) {
		@Override
		public TableCellEditor getEditor() {
			return VarDataTypeEditor.INSTANCE;
		}
	},
	REPR("Repr", String.class, OutputRow::getRepr);

	final String header;
	final Class<?> cls;
	final Function<OutputRow, Object> getter;
	final BiConsumer<OutputRow, Object> setter;

	@SuppressWarnings("unchecked")
	private <T> OutputColumn(String header, Class<T> cls, Function<OutputRow, T> getter,
			BiConsumer<OutputRow, T> setter) {
		this.header = header;
		this.cls = cls;
		this.getter = (Function<OutputRow, Object>) getter;
		this.setter = (BiConsumer<OutputRow, Object>) setter;
	}

	private <T> OutputColumn(String header, Class<T> cls, Function<OutputRow, T> getter) {
		this(header, cls, getter, null);
	}

	@Override
	public Class<?> getValueClass() {
		return cls;
	}

	@Override
	public Object getValueOf(OutputRow row) {
		return getter.apply(row);
	}

	@Override
	public boolean isEditable(OutputRow row) {
		return setter != null;
	}

	@Override
	public void setValueOf(OutputRow row, Object value) {
		setter.accept(row, value);
	}

	@Override
	public String getHeader() {
		return header;
	}
}
