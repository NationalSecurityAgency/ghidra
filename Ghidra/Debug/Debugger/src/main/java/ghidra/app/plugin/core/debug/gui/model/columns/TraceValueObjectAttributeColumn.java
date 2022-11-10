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

import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueProperty;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.dbg.target.TargetAttacher.TargetAttachKindSet;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetSteppable.TargetStepKindSet;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.AttributeSchema;
import ghidra.trace.model.target.TraceObject;

public class TraceValueObjectAttributeColumn<T>
		extends TraceValueObjectPropertyColumn<T> {

	public static Class<?> computeColumnType(SchemaContext ctx, AttributeSchema attributeSchema) {
		TargetObjectSchema schema = ctx.getSchema(attributeSchema.getSchema());
		Class<?> type = schema.getType();
		if (type == TargetObject.class) {
			return TraceObject.class;
		}
		if (type == TargetExecutionState.class) {
			return String.class;
		}
		if (type == TargetParameterMap.class) {
			return String.class;
		}
		if (type == TargetAttachKindSet.class) {
			return String.class;
		}
		if (type == TargetBreakpointKindSet.class) {
			return String.class;
		}
		if (type == TargetStepKindSet.class) {
			return String.class;
		}
		return type;
	}

	protected final String attributeName;

	public TraceValueObjectAttributeColumn(String attributeName, Class<T> attributeType) {
		super(attributeType);
		this.attributeName = attributeName;
	}

	@Override
	public String getColumnName() {
		/**
		 * TODO: These are going to have "_"-prefixed things.... Sure, they're "hidden", but if we
		 * remove them, we're going to hide important info. I'd like a way in the schema to specify
		 * which "interface attribute" an attribute satisfies. That way, the name can be
		 * human-friendly, but the interface can still find what it needs.
		 */
		return attributeName;
	}

	@Override
	public ValueProperty<T> getProperty(ValueRow row) {
		return row.getAttribute(attributeName, propertyType);
	}
}
