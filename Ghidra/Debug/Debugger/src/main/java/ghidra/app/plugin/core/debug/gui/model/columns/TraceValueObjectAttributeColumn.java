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
import ghidra.trace.model.TraceExecutionState;
import ghidra.trace.model.target.schema.SchemaContext;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.model.target.schema.TraceObjectSchema.AttributeSchema;

/**
 * A column which displays the object's value for a given attribute
 *
 * @param <T> the type of the attribute
 */
public class TraceValueObjectAttributeColumn<T> extends TraceValueObjectPropertyColumn<T> {

	/**
	 * Get the type of a given attribute for the model schema
	 * 
	 * @param ctx the schema context
	 * @param attributeSchema the attribute entry from the schema
	 * @return the type, as a Java class
	 */
	public static Class<?> computeAttributeType(SchemaContext ctx,
			AttributeSchema attributeSchema) {
		TraceObjectSchema schema = ctx.getSchema(attributeSchema.getSchema());
		Class<?> type = schema.getType();
		if (type == TraceExecutionState.class) {
			return String.class;
		}
		return type;
	}

	protected final String attributeName;

	/**
	 * Construct an attribute-value column
	 * 
	 * @param attributeName the name of the attribute
	 * @param attributeType the type of the attribute (see
	 *            {@link #computeAttributeType(SchemaContext, AttributeSchema)})
	 */
	public TraceValueObjectAttributeColumn(String attributeName, Class<T> attributeType) {
		super(attributeType);
		this.attributeName = attributeName;
	}

	@Override
	public String getColumnName() {
		return attributeName;
	}

	@Override
	public ValueProperty<T> getProperty(ValueRow row) {
		return row.getAttribute(attributeName, propertyType);
	}
}
