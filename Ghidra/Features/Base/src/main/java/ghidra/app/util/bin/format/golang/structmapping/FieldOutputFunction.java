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

import java.io.IOException;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;

/**
 * A function that helps construct a Ghidra {@link DataType} from annotated field information
 * found in a Java class.
 * 
 * @param <T>
 */
public interface FieldOutputFunction<T> {
	void addFieldToStructure(StructureContext<T> context, Structure structure,
			FieldOutputInfo<T> fieldOutputInfo) throws IOException;
}
