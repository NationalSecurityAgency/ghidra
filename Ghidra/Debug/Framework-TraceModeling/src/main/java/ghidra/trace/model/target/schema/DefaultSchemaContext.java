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
package ghidra.trace.model.target.schema;

import java.util.*;

import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;
import ghidra.util.Msg;

/**
 * The default implementation of a schema context
 */
public class DefaultSchemaContext implements SchemaContext {
	private final Map<SchemaName, TraceObjectSchema> schemas = new LinkedHashMap<>();

	public DefaultSchemaContext() {
		for (PrimitiveTraceObjectSchema schema : PrimitiveTraceObjectSchema.values()) {
			schemas.put(schema.getName(), schema);
		}
	}

	public DefaultSchemaContext(SchemaContext ctx) {
		this();
		for (TraceObjectSchema schema : ctx.getAllSchemas()) {
			if (!(schema instanceof PrimitiveTraceObjectSchema)) {
				this.builder(schema).buildAndAdd();
			}
		}
	}

	public SchemaBuilder builder(TraceObjectSchema schema) {
		return new SchemaBuilder(this, schema);
	}

	public SchemaBuilder builder(SchemaName name) {
		return new SchemaBuilder(this, name);
	}

	public SchemaBuilder modify(SchemaName name) {
		return new SchemaBuilder(this, getSchema(name));
	}

	public synchronized void putSchema(TraceObjectSchema schema) {
		if (schemas.containsKey(schema.getName())) {
			throw new IllegalArgumentException("Name already in context: " + schema.getName());
		}
		schemas.put(schema.getName(), schema);
	}

	public synchronized void replaceSchema(TraceObjectSchema schema) {
		schemas.put(schema.getName(), schema);
	}

	@Override
	public synchronized TraceObjectSchema getSchemaOrNull(SchemaName name) {
		return schemas.get(name);
	}

	@Override
	public synchronized TraceObjectSchema getSchema(SchemaName name) {
		TraceObjectSchema schema = schemas.get(name);
		if (schema == null) {
			Msg.error(this, "No such schema name: " + name);
			return PrimitiveTraceObjectSchema.ANY;
		}
		return schema;
	}

	@Override
	public synchronized SequencedSet<TraceObjectSchema> getAllSchemas() {
		return Collections.unmodifiableSequencedSet(new LinkedHashSet<>(schemas.values()));
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		for (TraceObjectSchema s : schemas.values()) {
			sb.append(s + "\n");
		}
		return sb.toString();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof DefaultSchemaContext that) {
			return Objects.equals(this.schemas, that.schemas);
		}
		if (obj instanceof SchemaContext that) {
			return this.schemas.values().equals(that.getAllSchemas());
		}
		return false;
	}

	@Override
	public int hashCode() {
		return schemas.hashCode();
	}
}
