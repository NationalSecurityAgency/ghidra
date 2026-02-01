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

import java.util.SequencedSet;

import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;

/**
 * A collection of related schemas all for the same trace or target
 */
public interface SchemaContext {
	/**
	 * Resolve a schema in this context by name
	 * 
	 * <p>
	 * Note that resolving a name generated outside of this context may have undefined results.
	 * 
	 * @param name the schema's name
	 * @return the schema or {@link PrimitiveTraceObjectSchema#ANY} if no schema by the given name
	 *         exists
	 */
	TraceObjectSchema getSchema(SchemaName name);

	/**
	 * Resolve a schema in this context by name
	 * 
	 * @param name the schema's name
	 * @return the schema, or null if no schema by the given name exists
	 */
	TraceObjectSchema getSchemaOrNull(SchemaName name);

	/**
	 * Collect all schemas in this context
	 * 
	 * @return the set of all schemas
	 */
	SequencedSet<TraceObjectSchema> getAllSchemas();
}
