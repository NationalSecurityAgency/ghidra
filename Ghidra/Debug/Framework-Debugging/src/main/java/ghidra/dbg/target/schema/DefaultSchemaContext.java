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
package ghidra.dbg.target.schema;

import java.util.*;

import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;

public class DefaultSchemaContext implements SchemaContext {
	private final Map<SchemaName, TargetObjectSchema> schemas = new LinkedHashMap<>();

	public DefaultSchemaContext() {
		for (EnumerableTargetObjectSchema schema : EnumerableTargetObjectSchema.values()) {
			schemas.put(schema.getName(), schema);
		}
	}

	public SchemaBuilder builder(SchemaName name) {
		return new SchemaBuilder(this, name);
	}

	public synchronized void putSchema(TargetObjectSchema schema) {
		if (schemas.containsKey(schema.getName())) {
			throw new IllegalArgumentException("Name already in context: " + schema.getName());
		}
		schemas.put(schema.getName(), schema);
	}

	@Override
	public synchronized TargetObjectSchema getSchemaOrNull(SchemaName name) {
		return schemas.get(name);
	}

	@Override
	public synchronized TargetObjectSchema getSchema(SchemaName name) {
		return Objects.requireNonNull(schemas.get(name), "No such schema name: " + name);
	}

	@Override
	public synchronized Set<TargetObjectSchema> getAllSchemas() {
		// Set.copyOf does not preserve iteration order
		return Collections.unmodifiableSet(new LinkedHashSet<>(schemas.values()));
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		for (TargetObjectSchema s : schemas.values()) {
			sb.append(s + "\n");
		}
		return sb.toString();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof DefaultSchemaContext) {
			DefaultSchemaContext that = (DefaultSchemaContext) obj;
			return Objects.equals(this.schemas, that.schemas);
		}
		if (obj instanceof SchemaContext) {
			SchemaContext that = (SchemaContext) obj;
			return this.schemas.values().equals(that.getAllSchemas());
		}
		return false;
	}

	@Override
	public int hashCode() {
		return schemas.hashCode();
	}
}
