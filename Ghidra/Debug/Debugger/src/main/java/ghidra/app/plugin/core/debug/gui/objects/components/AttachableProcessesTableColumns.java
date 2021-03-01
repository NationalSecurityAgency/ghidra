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
import ghidra.dbg.target.TargetAttachable;

public enum AttachableProcessesTableColumns
	implements EnumeratedTableColumn<AttachableProcessesTableColumns, TargetAttachable> {
	ID("ID", String.class, TargetAttachable::getName),
	NAME("Name", String.class, TargetAttachable::getTypeHint);

	private final String header;
	private final Function<TargetAttachable, ?> func;
	private Class<?> cls;

	<T> AttachableProcessesTableColumns(String header, Class<T> cls,
			Function<TargetAttachable, T> func) {
		this.header = header;
		this.cls = cls;
		this.func = func;
	}

	@Override
	public Class<?> getValueClass() {
		return cls;
	}

	@Override
	public Object getValueOf(TargetAttachable proc) {
		return func.apply(proc);
	}

	@Override
	public String getHeader() {
		return header;
	}
}
