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

import java.util.Set;

import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;

/**
 * A collection of related schemas
 */
public interface SchemaContext {
	/**
	 * Resolve a schema in this context by name
	 * 
	 * <p>
	 * Note that resolving a name generated outside of this context may have undefined results. In
	 * most cases, it will resolve to the schema whose name has the same string representation, but
	 * it might instead throw a {@link NullPointerException}.
	 * 
	 * @param name the schema's name
	 * @return the schema
	 * @throws NullPointerException if no schema by the given name exists
	 */
	TargetObjectSchema getSchema(SchemaName name);

	/**
	 * Resolve a schema in this context by name
	 * 
	 * @param name the schema's name
	 * @return the schema, or null if no schema by the given name exists
	 */
	TargetObjectSchema getSchemaOrNull(SchemaName name);

	/**
	 * Collect all schemas in this context
	 * 
	 * @return the set of all schemas
	 */
	Set<TargetObjectSchema> getAllSchemas();
}
