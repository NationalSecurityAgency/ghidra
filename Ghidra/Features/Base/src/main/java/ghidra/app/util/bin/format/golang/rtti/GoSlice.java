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
package ghidra.app.util.bin.format.golang.rtti;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.BinaryReader.ReaderFunction;
import ghidra.app.util.bin.format.golang.rtti.types.GoSliceType;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * A structure that represents a golang slice instance (similar to a java ArrayList).  Not to be
 * confused with a {@link GoSliceType}, which is RTTI info about a slice type.
 * <p>
 * An initialized static image of a slice found in a go binary will tend to have len==cap (full).
 * <p>
 * Like java's type erasure for generics, a golang slice instance does not have type information 
 * about the elements found in the array blob (nor the size of the blob).
 * <p>
 */
@StructureMapping(structureName = "runtime.slice")
public class GoSlice implements StructureMarkup<GoSlice> {

	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoSlice> context;

	@FieldMapping
	private long array;	// pointer to data
	@FieldMapping
	private long len;	// number of active elements
	@FieldMapping
	private long cap;	// number of elements that can be stored in the array

	public GoSlice() {
		// emtpy
	}

	/**
	 * Creates an artificial slice instance using the supplied values.
	 * 
	 * @param array offset of the slice's data
	 * @param len number of initialized elements in the slice
	 * @param cap total number of elements in the data array
	 * @param programContext the go binary that contains the slice
	 */
	public GoSlice(long array, long len, long cap, GoRttiMapper programContext) {
		this.array = array;
		this.len = len;
		this.cap = cap;
		this.programContext = programContext;
	}

	/**
	 * Returns the {@link DataType} of elements of this slice, as detected by the type information
	 * contained in the struct field that contains this slice.
	 * <p>
	 * Returns null if this slice instance was not nested (contained) in a structure.  If the
	 * slice data type wasn't a specialized slice data type (it was "runtime.slice" instead of
	 * "[]element"), void data type will be returned.
	 * 
	 * @return data type of the elements of this slice, if possible, or null
	 */
	public DataType getElementDataType() {
		DataType dt = context != null ? context.getContainingFieldDataType() : null;
		if (dt != null && dt instanceof Structure struct && struct.getNumDefinedComponents() > 0) {
			int elementPtrFieldOrdinal = 0;	// hacky hard coded knowledge that the pointer to the data is the first element of the slice struct
			DataTypeComponent elementPtrDTC = struct.getComponent(elementPtrFieldOrdinal);
			DataType elementPtrDT = elementPtrDTC.getDataType();
			return elementPtrDT instanceof Pointer ptrDT ? ptrDT.getDataType() : null;
		}
		return null;
	}

	/**
	 * Return a artificial view of a portion of this slice's contents.
	 * 
	 * @param startElement index of element that will be the new sub-slice's starting element
	 * @param elementCount number of elements to include in new sub-slice
	 * @param elementSize size of an individual element
	 * @return new {@link GoSlice} instance that is limited to a portion of this slice
	 */
	public GoSlice getSubSlice(long startElement, long elementCount, long elementSize) {
		return new GoSlice(array + (startElement * elementSize), elementCount, elementCount,
			programContext);
	}

	/**
	 * Returns true if this slice seems valid.
	 * 
	 * @return boolean true if array blob is a valid memory location
	 */
	public boolean isValid() {
		return array != 0 && isValid(1);
	}

	/**
	 * Returns true if this slice seems valid.
	 * 
	 * @param elementSize size of elements in this slice 
	 * @return boolean true if array blob is a valid memory location
	 */
	public boolean isValid(int elementSize) {
		try {
			Memory memory = programContext.getProgram().getMemory();
			Address arrayAddr = getArrayAddress();
			return memory.contains(arrayAddr) &&
				memory.contains(arrayAddr.addNoWrap(len * elementSize));
		}
		catch (AddressOverflowException | AddressOutOfBoundsException e) {
			return false;
		}
	}

	/**
	 * Returns address of the array blob.
	 * 
	 * @return location of the array blob
	 */
	public long getArrayOffset() {
		return array;
	}

	/**
	 * Returns the address of the array blob
	 * @return address of the array blob
	 */
	public Address getArrayAddress() {
		return programContext.getDataAddress(array);
	}

	/**
	 * Returns the address of the end of the array.
	 * 
	 * @param elementClass structure mapped class
	 * @return location of the end of the array blob
	 */
	public long getArrayEnd(Class<?> elementClass) {
		StructureMappingInfo<?> elementSMI =
			context.getDataTypeMapper().getStructureMappingInfo(elementClass);
		return getElementOffset(elementSMI.getStructureLength(), len);
	}

	/**
	 * Returns the number of initialized elements 
	 * 
	 * @return number of initialized elements
	 */
	public long getLen() {
		return len;
	}

	/**
	 * Returns the number of elements allocated in the array blob. (capacity)
	 * 
	 * @return number of allocated elements in the array blob
	 */
	public long getCap() {
		return cap;
	}

	/**
	 * Returns true if this slice's element count is equal to the slice's capacity.  This is
	 * typically true for all slices that are static.
	 * 
	 * @return boolean true if this slice's element count is equal to capacity
	 */
	public boolean isFull() {
		return len == cap;
	}

	/**
	 * Returns true if this slice contains the specified offset.
	 * 
	 * @param offset memory offset in question
	 * @param sizeofElement size of elements in this slice
	 * @return true if this slice contains the specified offset
	 */
	public boolean containsOffset(long offset, int sizeofElement) {
		return array <= offset && offset < getElementOffset(sizeofElement, cap);
	}

	/**
	 * Returns the offset of the specified element
	 * 
	 * @param elementSize size of elements in this slice
	 * @param elementIndex index of desired element
	 * @return offset of element
	 */
	public long getElementOffset(long elementSize, long elementIndex) {
		return array + elementSize * elementIndex;
	}

	/**
	 * Reads the content of the slice, treating each element as an instance of the specified
	 * structure mapped class.
	 * 
	 * @param <T> struct mapped type of element
	 * @param clazz element type 
	 * @return list of instances
	 * @throws IOException if error reading an element
	 */
	public <T> List<T> readList(Class<T> clazz) throws IOException {
		return readList((reader) -> programContext.readStructure(clazz, reader));
	}

	/**
	 * Reads the contents of the slice, treating each element as an instance of an object that can
	 * be read using the supplied reading function.
	 * 
	 * @param <T> struct mapped type of element
	 * @param readFunc function that will read an instance from a BinaryReader
	 * @return list of instances
	 * @throws IOException if error reading an element
	 */
	public <T> List<T> readList(ReaderFunction<T> readFunc) throws IOException {
		List<T> result = new ArrayList<>();

		long elementSize = 0;
		BinaryReader reader = programContext.getReader(array);
		for (int i = 0; i < len; i++) {
			T t = readFunc.get(reader);
			result.add(t);
			if (i == 0) {
				elementSize = reader.getPointerIndex() - array;
			}
			else {
				// ensure that the reader func is doing correct thing
				if (elementSize > 0 &&
					reader.getPointerIndex() != getElementOffset(elementSize, i + 1)) {
					Msg.warn(this, "Bad element size when reading slice element (size: %d) at %d"
							.formatted(elementSize, reader.getPointerIndex()));
					elementSize = 0;
				}
			}
		}
		return result;
	}

	/**
	 * Treats this slice as a array of unsigned integers, of the specified intSize.
	 * <p>
	 * @param intSize size of integer
	 * @return array of longs, containing the (possibly smaller) integers contained in the slice
	 * @throws IOException if error reading
	 */
	public long[] readUIntList(int intSize) throws IOException {
		BinaryReader reader = programContext.getReader(array);
		return readUIntList(reader, array, intSize, (int) len);
	}

	/**
	 * Reads an unsigned int element from this slice.
	 * 
	 * @param intSize size of ints
	 * @param elementIndex index of element
	 * @return unsigned int value
	 * @throws IOException if error reading element
	 */
	public long readUIntElement(int intSize, int elementIndex) throws IOException {
		return getElementReader(intSize, elementIndex).readNextUnsignedValue(intSize);
	}

	/**
	 * Returns a {@link BinaryReader} positioned at the specified slice element.
	 * 
	 * @param elementSize size of elements in this slice
	 * @param elementIndex index of desired element
	 * @return {@link BinaryReader} positioned at specified element
	 */
	public BinaryReader getElementReader(int elementSize, int elementIndex) {
		BinaryReader reader = programContext.getReader(getElementOffset(elementSize, elementIndex));
		return reader;
	}

	/**
	 * Marks up the memory occupied by the array elements with a name and a Ghidra ArrayDataType,
	 * which has elements who's type is determined by the specified structure class. 
	 * 
	 * @param sliceName used to label the memory location
	 * @param namespaceName namespace the label symbol should be placed in
	 * @param elementClazz structure mapped class of the element of the array  
	 * @param ptr boolean flag, if true the element type is really a pointer to the supplied
	 * data type
	 * @param session state and methods to assist marking up the program
	 * @throws IOException if error
	 */
	public void markupArray(String sliceName, String namespaceName, Class<?> elementClazz,
			boolean ptr, MarkupSession session) throws IOException {
		DataType dt = programContext.getStructureDataType(elementClazz);
		markupArray(sliceName, namespaceName, dt, ptr, session);
	}

	/**
	 * Marks up the memory occupied by the array elements with a name and a Ghidra ArrayDataType.
	 * 
	 * @param sliceName used to label the memory location
	 * @param namespaceName namespace the label symbol should be placed in
	 * @param elementType Ghidra datatype of the array elements, null ok if ptr == true 
	 * @param ptr boolean flag, if true the element type is really a pointer to the supplied
	 * data type
	 * @param session state and methods to assist marking up the program
	 * @throws IOException if error
	 */
	public void markupArray(String sliceName, String namespaceName, DataType elementType,
			boolean ptr, MarkupSession session) throws IOException {
		if (len == 0 || !isValid()) {
			return;
		}

		DataTypeManager dtm = programContext.getDTM();
		if (ptr) {
			elementType = new PointerDataType(elementType, programContext.getPtrSize(), dtm);
		}

		ArrayDataType arrayDT = new ArrayDataType(elementType, (int) cap, -1, dtm);
		Address addr = programContext.getDataAddress(array);
		session.markupAddress(addr, arrayDT);
		if (sliceName != null) {
			session.labelAddress(addr, sliceName, namespaceName);
		}
	}

	/**
	 * Marks up each element of the array, useful when the elements are themselves structures.
	 * 
	 * @param <T> element type
	 * @param clazz structure mapped class of element
	 * @param session state and methods to assist marking up the program
	 * @return list of element instances
	 * @throws IOException if error reading
	 * @throws CancelledException if cancelled 
	 */
	public <T> List<T> markupArrayElements(Class<T> clazz, MarkupSession session)
			throws IOException, CancelledException {
		if (len == 0) {
			return List.of();
		}

		List<T> elementList = readList(clazz);
		session.markup(elementList, true);
		return elementList;
	}

	/**
	 * Marks up each element of the array with an outbound reference to the corresponding address
	 * in the targetAddrs list.
	 * <p>
	 * Useful when marking up an array of offsets.
	 * <p>
	 * The Listing UI doesn't show the outbound reference from each element (for arrays of primitive
	 * types), but the target will show the inbound reference.
	 *  
	 * @param elementSize size of each element in the array
	 * @param targetAddrs list of addresses, should be same size as this slice
	 * @param session state and methods to assist marking up the program
	 * @throws IOException if error creating references
	 */
	public void markupElementReferences(int elementSize, List<Address> targetAddrs,
			MarkupSession session) throws IOException {
		if (!targetAddrs.isEmpty()) {
			session.markupArrayElementReferences(getArrayAddress(), elementSize, targetAddrs);
		}
	}

	private static long[] readUIntList(BinaryReader reader, long index, int intSize, int count)
			throws IOException {
		long[] result = new long[count];

		for (int i = 0; i < count; i++) {
			long l = reader.readUnsignedValue(index, intSize);
			result[i] = l;
			index += intSize;
		}
		return result;
	}

	@Override
	public String getStructureLabel() throws IOException {
		return "slice[%d]_%s".formatted(len, context.getStructureAddress());
	}

	@Override
	public StructureContext<GoSlice> getStructureContext() {
		return context;
	}
}
