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

import java.io.IOException;
import java.util.Set;

import ghidra.app.util.bin.format.golang.rtti.GoTypeManager;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.app.util.viewer.field.AddressAnnotatedStringHandler;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

/**
 * Golang type info about a specific map type.
 * <p>
 * See {@link GoTypeManager#getMapGoType()} or the "runtime.hmap" type for the definition of
 * a instance of a map variable in memory. 
 */
@StructureMapping(structureName = {"runtime.maptype", "internal/abi.MapType"})
public class GoMapType extends GoType {

	@FieldMapping
	@MarkupReference("getKey")
	private long key;	// ptr to type

	@FieldMapping
	@MarkupReference("getElement")
	private long elem;	// ptr to type

	@FieldMapping
	@MarkupReference("getBucket")
	private long bucket;	// ptr to type

	@FieldMapping
	private long hasher;	// pointer to "func(Pointer, pointer) pointer"

	@FieldMapping
	private int keysize;

	@FieldMapping(fieldName = {"elemsize", "ValueSize"})
	private int elemsize;

	@FieldMapping
	private int bucketsize;

	@FieldMapping
	private int flags;

	public GoMapType() {
		// empty
	}

	/**
	 * Returns the GoType that defines the map's key, referenced by the key field's markup annotation
	 * 
	 * @return GoType that defines the map's key
	 * @throws IOException if error reading data
	 */
	@Markup
	public GoType getKey() throws IOException {
		return programContext.getGoTypes().getType(key);
	}

	/**
	 * Returns the GoType that defines the map's element, referenced by the element field's markup annotation
	 * 
	 * @return GoType that defines the map's element
	 * @throws IOException if error reading data
	 */
	@Markup
	public GoType getElement() throws IOException {
		return programContext.getGoTypes().getType(elem);
	}

	/**
	 * Returns the GoType that defines the map's bucket, referenced by the bucket field's markup annotation
	 * 
	 * @return GoType that defines the map's bucket
	 * @throws IOException if error reading data
	 */
	@Markup
	public GoType getBucket() throws IOException {
		return programContext.getGoTypes().getType(bucket);
	}

	@Override
	public DataType recoverDataType(GoTypeManager goTypes) throws IOException {
		GoType mapGoType = goTypes.getMapGoType();
		if (mapGoType == null) {
			// if we couldn't find the underlying/hidden runtime.hmap struct type, just return
			// a void*
			return goTypes.getVoidPtrDT();
		}
		DataType mapDT = goTypes.getGhidraDataType(mapGoType);
		Pointer ptrMapDt = goTypes.getDTM().getPointer(mapDT);
		if (typ.getSize() != ptrMapDt.getLength()) {
			Msg.warn(this, "Size mismatch between map type and recovered type");
		}
		TypedefDataType typedef =
			new TypedefDataType(goTypes.getCP(this), goTypes.getTypeName(this), ptrMapDt,
				goTypes.getDTM());
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

	@Override
	protected String getTypeDeclString() throws IOException {
		// type CustomMaptype map[keykey]valuetype
		String selfName = getName();
		String keyName = getKey().getName();
		String elemName = getElement().getName();
		String defStr = "map[%s]%s".formatted(keyName, elemName);
		String defStrWithLinks = "map[%s]%s".formatted(
			AddressAnnotatedStringHandler.createAddressAnnotationString(key, keyName),
			AddressAnnotatedStringHandler.createAddressAnnotationString(elem, elemName));
		boolean hasName = !defStr.equals(selfName);

		return "type %s%s".formatted(hasName ? selfName + " " : "", defStrWithLinks);
	}

	@Override
	public boolean isValid() {
		return super.isValid() && typ.getSize() == programContext.getPtrSize();
	}

}
