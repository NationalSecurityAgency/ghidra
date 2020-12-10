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
package ghidra.app.plugin.core.debug.gui.timeline;

import java.util.function.BiConsumer;
import java.util.function.Function;

import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;

public enum TimelineTableColumns
	implements EnumeratedTableColumn<TimelineTableColumns, TimelineRow> {
	NAME("Name", String.class, TimelineRow::getName, TimelineRow::setName),
	CREATED("Created", Long.class, TimelineRow::getCreationTick),
	DESTROYED("Destroyed", String.class, TimelineRow::getDestructionTick),
	STATE("State", TimelineState.class, TimelineRow::getState),
	COMMENT("Comment", String.class, TimelineRow::getComment, TimelineRow::setComment);

	private final String header;
	private final Function<TimelineRow, ?> getter;
	private final BiConsumer<TimelineRow, Object> setter;
	private final Class<?> cls;

	<T> TimelineTableColumns(String header, Class<T> cls, Function<TimelineRow, T> getter) {
		this(header, cls, getter, null);
	}

	@SuppressWarnings("unchecked")
	<T> TimelineTableColumns(String header, Class<T> cls, Function<TimelineRow, T> getter,
			BiConsumer<TimelineRow, T> setter) {
		this.header = header;
		this.cls = cls;
		this.getter = getter;
		this.setter = (BiConsumer<TimelineRow, Object>) setter;
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
	public Object getValueOf(TimelineRow row) {
		return getter.apply(row);
	}

	@Override
	public boolean isEditable(TimelineRow row) {
		return setter != null;
	}

	@Override
	public void setValueOf(TimelineRow row, Object value) {
		setter.accept(row, value);
	}
}
