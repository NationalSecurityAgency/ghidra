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
import ghidra.program.model.data.*;
import ghidra.util.Msg;

@StructureMapping(structureName = "runtime.maptype")
public class GoMapType extends GoType {

	@FieldMapping
	private long key;	// ptr to type

	@FieldMapping
	private long elem;	// ptr to type

	@FieldMapping
	private long bucket;	// ptr to type

	@FieldMapping
	private long hasher;	// pointer to "func(Pointer, pointer) pointer"

	@FieldMapping
	private int keysize;

	@FieldMapping
	private int elemsize;

	@FieldMapping
	private int bucketsize;

	@FieldMapping
	private int flags;

	public GoMapType() {
	}

	@Markup
	public GoType getKey() throws IOException {
		return programContext.getGoType(key);
	}

	@Markup
	public GoType getElement() throws IOException {
		return programContext.getGoType(elem);
	}

	@Markup
	public GoType getBucket() throws IOException {
		return programContext.getGoType(bucket);
	}

	@Override
	public DataType recoverDataType() throws IOException {
		GoType mapGoType = programContext.getMapGoType();
		if (mapGoType == null) {
			// if we couldn't find the underlying/hidden runtime.hmap struct type, just return
			// a void*
			return programContext.getDTM().getPointer(null);
		}
		DataType mapDT = mapGoType.recoverDataType();
		Pointer ptrMapDt = programContext.getDTM().getPointer(mapDT);
		if (typ.getSize() != ptrMapDt.getLength()) {
			Msg.warn(this, "Size mismatch between map type and recovered type");
		}
		TypedefDataType typedef = new TypedefDataType(programContext.getRecoveredTypesCp(),
			getStructureName(), ptrMapDt, programContext.getDTM());
		return typedef;
	}

	@Override
	public boolean discoverGoTypes(Set<Long> discoveredTypes) throws IOException {
		if (!super.discoverGoTypes(discoveredTypes)) {
			return false;
		}
		GoType keyType = getKey();
		GoType elemType = getElement();
		GoType bucketType = getBucket();
		if (keyType != null) {
			keyType.discoverGoTypes(discoveredTypes);
		}
		if (elemType != null) {
			elemType.discoverGoTypes(discoveredTypes);
		}
		if (bucketType != null) {
			bucketType.discoverGoTypes(discoveredTypes);
		}
		return true;
	}
}
