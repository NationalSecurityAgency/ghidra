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
package ghidra.app.plugin.core.debug.gui.model.columns;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueProperty;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;

public class TraceValueObjectEditableAttributeColumn<T> extends TraceValueObjectAttributeColumn<T>
		implements EditableColumn<ValueRow, ValueProperty<T>, Trace> {
	public TraceValueObjectEditableAttributeColumn(String attributeName, Class<T> attributeType) {
		super(attributeName, attributeType);
	}

	@Override
	public boolean isEditable(ValueRow row, Settings settings, Trace dataSource,
			ServiceProvider serviceProvider) {
		return row != null;
	}

	@Override
	public void setValue(ValueRow row, ValueProperty<T> value, Settings settings, Trace dataSource,
			ServiceProvider serviceProvider) {
		TraceObject object = row.getValue().getChild();
		try (Transaction tx =
			object.getTrace().openTransaction("Edit column " + getColumnName())) {
			object.setAttribute(Lifespan.nowOn(row.currentSnap()), attributeName, value.getValue());
		}
	}
}
