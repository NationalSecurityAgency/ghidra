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
package ghidra.app.util.bin.format.golang.rtti.types;

import java.util.Set;

import java.io.IOException;

import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;

@StructureMapping(structureName = "runtime.arraytype")
public class GoArrayType extends GoType {

	@FieldMapping
	private long elem;  // pointer to element type

	@FieldMapping
	private long slice;	// pointer to slice type

	@FieldMapping
	private long len;

	public GoArrayType() {
	}

	@Markup
	public GoType getElement() throws IOException {
		return programContext.getGoType(elem);
	}

	@Markup
	public GoType getSliceType() throws IOException {
		return programContext.getGoType(slice);
	}

	@Override
	public DataType recoverDataType() throws IOException {
		DataType elementDt = programContext.getRecoveredType(getElement());
		DataType self = programContext.getCachedRecoveredDataType(this);
		if (self != null) {
			return self;
		}
		return new ArrayDataType(elementDt, (int) len, -1);
	}

	@Override
	public boolean discoverGoTypes(Set<Long> discoveredTypes) throws IOException {
		if (!super.discoverGoTypes(discoveredTypes)) {
			return false;
		}
		GoType elementType = getElement();
		GoType sliceType = getSliceType();
		if (elementType != null) {
			elementType.discoverGoTypes(discoveredTypes);
		}
		if (sliceType != null) {
			sliceType.discoverGoTypes(discoveredTypes);
		}
		return true;
	}

}
