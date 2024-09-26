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
package ghidra.app.util.bin.format.golang.structmapping;

/**
 * Context passed to StructureMapping logic when binding a structure's fields to a java class's
 * fields.
 */
public interface DataTypeMapperContext {

	/**
	 * Tests if a field should be included when creating bindings between a structure and a class.
	 * 
	 * @param presentWhen free-form string that is interpreted by each {@link DataTypeMapper}
	 * @return boolean true if field should be bound, false if field should not be bound
	 */
	boolean isFieldPresent(String presentWhen);

}
