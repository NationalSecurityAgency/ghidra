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
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;

@StructureMapping(structureName = "runtime.slice")
public class GoSlice {

	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoSlice> context;

	@FieldMapping
	private long array;
	@FieldMapping
	private long len;
	@FieldMapping
	private long cap;

	public GoSlice() {
		// emtpy
	}

	public GoSlice(long array, long len, long cap) {
		this(array, len, cap, null);
	}

	public GoSlice(long array, long len, long cap, GoRttiMapper programContext) {
		this.array = array;
		this.len = len;
		this.cap = cap;
		this.programContext = programContext;
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
		return new GoSlice(array + (startElement * elementSize), elementCount, elementCount, programContext);
	}

	public boolean isValid() {
		return array != 0 && isValid(1);
	}

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

	public long getArrayOffset() {
		return array;
	}

	public Address getArrayAddress() {
		return programContext.getDataAddress(array);
	}

	public long getArrayEnd(Class<?> elementClass) {
		StructureMappingInfo<?> elementSMI =
			context.getDataTypeMapper().getStructureMappingInfo(elementClass);
		int elementLength = elementSMI.getStructureLength();
		return array + len * elementLength;
	}

	public long getLen() {
		return len;
	}

	public long getCap() {
		return cap;
	}

	public boolean isFull() {
		return len == cap;
	}

	public boolean isOffsetWithinData(long offset, int sizeofElement) {
		return array <= offset && offset < array + (cap * sizeofElement);
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
				if (elementSize > 0 && reader.getPointerIndex() != array + (i + 1) * elementSize) {
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
	 * Marks up the memory occupied by the array elements with a name and a Ghidra ArrayDataType,
	 * which has elements who's type is determined by the specified structure class. 
	 * 
	 * @param sliceName used to label the memory location
	 * @param elementClazz structure mapped class of the element of the array  
	 * @param ptr boolean flag, if true the element type is really a pointer to the supplied
	 * data type
	 * @param session state and methods to assist marking up the program
	 * @throws IOException if error
	 */
	public void markupArray(String sliceName, Class<?> elementClazz, boolean ptr,
			MarkupSession session) throws IOException {
		DataType dt = programContext.getStructureDataType(elementClazz);
		markupArray(sliceName, dt, ptr, session);
	}

	/**
	 * Marks up the memory occupied by the array elements with a name and a Ghidra ArrayDataType.
	 * 
	 * @param sliceName used to label the memory location
	 * @param elementType Ghidra datatype of the array elements, null ok if ptr == true 
	 * @param ptr boolean flag, if true the element type is really a pointer to the supplied
	 * data type
	 * @param session state and methods to assist marking up the program
	 * @throws IOException if error
	 */
	public void markupArray(String sliceName, DataType elementType, boolean ptr,
			MarkupSession session) throws IOException {
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
			session.labelAddress(addr, sliceName);
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
	 */
	public <T> List<T> markupArrayElements(Class<T> clazz, MarkupSession session)
			throws IOException {
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

}
