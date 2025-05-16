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
package ghidra.program.util;

import java.util.*;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

/**
 * Iterator that visits each defined string instance in the initialized memory of a Program 
 * or in the footprint of a specified data element.
 * <p>
 * Strings that are nested inside of composites or arrays are visited, not just the
 * parent/containing data element.
 * <p>
 * Not thread safe.
 */
public class DefinedStringIterator implements DataIterator {

	/**
	 * Creates a new iterator that traverses the entire Program's address space returning
	 * data instances that are strings.
	 *
	 * @param program Ghidra {@link Program} to search
	 * @return new iterator
	 */
	public static DefinedStringIterator forProgram(Program program) {
		return new DefinedStringIterator(program, null);
	}

	/**
	 * Creates a new iterator that traverses a portion of the Program's address space returning
	 * data instances that are strings.
	 *
	 * @param program Ghidra {@link Program} to search
	 * @param addrs addresses to limit the iteration to
	 * @return new iterator
	 */
	public static DefinedStringIterator forProgram(Program program, AddressSetView addrs) {
		return new DefinedStringIterator(program, addrs);
	}

	/**
	 * Creates a new iterator that traverses the address space of a single data item (ie. a
	 * composite or array data instance that needs to be recursed into).
	 *
	 * @param singleDataInstance Data instance
	 * @return new iterator
	 */
	public static DefinedStringIterator forDataInstance(Data singleDataInstance) {
		return new DefinedStringIterator(singleDataInstance);
	}

	/**
	 * LIFO stack of iterators.  Newly found iterators of sub-components are
	 * pushed onto the end and become the current iterator.  When an iterator is exhausted, 
	 * it is popped of the end and the uncovered iterator is now the current.    
	 */
	private Deque<DataIterator> itStack = new ArrayDeque<>();
	private Data currentDataResult;
	private int dataCandidateCount;  // mostly for tests to ensure we aren't doing unneeded work

	private DefinedStringIterator(Program program, AddressSetView addrs) {

		itStack.addLast(program.getListing()
				.getDefinedData(
					(addrs == null) ? program.getMemory().getAllInitializedAddressSet() : addrs,
					true));
	}

	private DefinedStringIterator(Data singleDataInstance) {
		itStack.addLast(DataIterator.of(singleDataInstance));
	}

	@Override
	public boolean hasNext() {
		updateNextResultIfNeeded();
		return currentDataResult != null;
	}

	@Override
	public Data next() {
		updateNextResultIfNeeded();
		if (currentDataResult == null) {
			throw new NoSuchElementException();
		}
		Data result = currentDataResult;
		currentDataResult = null;
		return result;
	}

	public int getDataCandidateCount() {
		return dataCandidateCount;
	}

	private DataIterator currentIt() {
		DataIterator it = null;
		while ((it = itStack.peekLast()) != null && !it.hasNext()) {
			itStack.removeLast();
		}
		return it;
	}

	private void updateNextResultIfNeeded() {
		DataIterator it = null;
		while (currentDataResult == null && (it = currentIt()) != null) {
			dataCandidateCount++;

			Data data = it.next();
			DataType dt = data.getBaseDataType();

			if (StringDataInstance.isString(data)) {
				currentDataResult = data;
				return;
			}
			else if (dt instanceof Array arrayDT) {
				// Will only get here for arrays of stuff that aren't char/wchar/int, which will
				// be handled earlier by isString(data)
				DataType elementDT = arrayDT.getDataType();
				if (containsStringDataType(elementDT)) {
					itStack.addLast(new ArrayElementIterator(data));
				}
				// side-effect: don't iterate arrays that have elements that aren't strings
			}
			else if (dt instanceof Composite comp && containsStringDataType(comp)) {
				itStack.addLast(new StructDtcIterator(data, comp));
			}
		}
	}

	private boolean containsStringDataType(DataType dt) {
		if (StringDataInstance.isStringDataType(dt)) {
			return true;
		}
		else if (dt instanceof Array arrayDT) {
			DataType elementDT = arrayDT.getDataType();
			return arrayDT.getNumElements() != 0 && containsStringDataType(elementDT);
		}
		else if (dt instanceof Structure struct) {
			// handle Structures and general Composite's separately so
			// we can focus on just the defined elements of a structure
			for (DataTypeComponent dtc : struct.getDefinedComponents()) {
				if (dtc.getLength() != 0 && containsStringDataType(dtc.getDataType())) {
					return true;
				}
			}
			return false;
		}
		else if (dt instanceof Composite comp) {
			for (DataTypeComponent dtc : comp.getComponents()) {
				if (containsStringDataType(dtc.getDataType())) {
					return true;
				}
			}
			return false;
		}
		else if (dt instanceof TypeDef tdDT) {
			return containsStringDataType(tdDT.getBaseDataType());
		}
		return false;
	}

	private static class StructDtcIterator implements DataIterator {
		private Data data;
		private int currentIndex = -1;
		private DataTypeComponent[] dtcs;

		public StructDtcIterator(Data data, Composite compDT) {
			this.data = data;
			this.dtcs = compDT.getDefinedComponents();
			advanceToNextGoodDtcIndex();
		}

		@Override
		public boolean hasNext() {
			return currentIndex < dtcs.length;
		}

		private void advanceToNextGoodDtcIndex() {
			currentIndex++;
			while (currentIndex < dtcs.length &&
				(dtcs[currentIndex].getLength() == 0 || dtcs[currentIndex].isBitFieldComponent())) {
				currentIndex++;
			}
		}

		@Override
		public Data next() {
			Data result = data.getComponentContaining(dtcs[currentIndex].getOffset());
			advanceToNextGoodDtcIndex();
			return result;
		}

	}

	private static class ArrayElementIterator implements DataIterator {
		private Data data;
		private int currentIndex;
		private int elementCount;

		public ArrayElementIterator(Data data) {
			this.data = data;
			this.elementCount = data.getNumComponents();
		}

		@Override
		public boolean hasNext() {
			return currentIndex < elementCount;
		}

		@Override
		public Data next() {
			Data result = data.getComponent(currentIndex);
			currentIndex++;
			return result;
		}

	}
}
