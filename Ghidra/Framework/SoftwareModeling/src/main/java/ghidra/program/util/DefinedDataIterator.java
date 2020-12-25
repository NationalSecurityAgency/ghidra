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
import java.util.function.Predicate;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

/**
 * Iterator that visits each defined data instance in the initialized memory of a Program or in the footprint of
 * a specified data element.
 * <p>
 * Data elements that are nested inside of composites or arrays are visited, not just the
 * parent/containing data element.
 */
public class DefinedDataIterator implements DataIterator {

	/**
	 * Creates a new iterator that traverses the entire Program's address space, returning
	 * data instances that successfully match the predicate.
	 *
	 * @param program Program to search
	 * @param dataTypePredicate {@link Predicate} that tests each data instance's {@link DataType}
	 * @return new iterator
	 */
	public static DefinedDataIterator byDataType(Program program,
			Predicate<DataType> dataTypePredicate) {
		return new DefinedDataIterator(program, null, dataTypePredicate, null);
	}

	/**
	 * Creates a new iterator that traverses a portion of the Program's address space, returning
	 * data instances that successfully match the predicate.
	 *
	 * @param program Program to search
	 * @param addresses addresses to limit the iteration to
	 * @param dataTypePredicate {@link Predicate} that tests each data instance's {@link DataType}
	 * @return new iterator
	 */
	public static DefinedDataIterator byDataType(Program program, AddressSetView addresses,
			Predicate<DataType> dataTypePredicate) {
		return new DefinedDataIterator(program, addresses, dataTypePredicate, null);
	}

	/**
	 * Creates a new iterator that traverses the entire Program's address space, returning
	 * data instances that successfully match the predicate.
	 *
	 * @param program Program to search
	 * @param dataInstancePredicate {@link Predicate} that tests each data instance's properties
	 * @return new iterator
	 */
	public static DefinedDataIterator byDataInstance(Program program,
			Predicate<Data> dataInstancePredicate) {
		return new DefinedDataIterator(program, null, null, dataInstancePredicate);
	}

	/**
	 * Creates a new iterator that traverses the entire Program's address space returning
	 * data instances that are strings.
	 *
	 * @param program Ghidra {@link Program} to search
	 * @return new iterator
	 */
	public static DefinedDataIterator definedStrings(Program program) {
		return new DefinedDataIterator(program, null,
			dataType -> StringDataInstance.isStringDataType(dataType),
			data -> StringDataInstance.isString(data));
	}

	/**
	 * Creates a new iterator that traverses a portion of the Program's address space returning
	 * data instances that are strings.
	 *
	 * @param program Ghidra {@link Program} to search
	 * @param addrs addresses to limit the iteration to
	 * @return new iterator
	 */
	public static DefinedDataIterator definedStrings(Program program, AddressSetView addrs) {
		return new DefinedDataIterator(program, addrs,
			dataType -> StringDataInstance.isStringDataType(dataType),
			data -> StringDataInstance.isString(data));
	}

	/**
	 * Creates a new iterator that traverses the address space of a single data item (ie. a
	 * composite or array data instance that needs to be recursed into).
	 *
	 * @param singleDataInstance Data instance
	 * @return new iterator
	 */
	public static DefinedDataIterator definedStrings(Data singleDataInstance) {
		return new DefinedDataIterator(singleDataInstance,
			dataType -> StringDataInstance.isStringDataType(dataType),
			data -> StringDataInstance.isString(data));
	}

	private Predicate<DataType> dataTypePredicate;
	private Predicate<Data> dataInstancePredicate;

	/**
	 * LIFO stack of iterators.  Newly found iterators of sub-components are
	 * pushed onto the end and become the current iterator.  When an iterator is exhausted, 
	 * it is popped of the end and the uncovered iterator is now the current.    
	 */
	private Deque<DataIterator> itStack = new ArrayDeque<>();
	private Data currentDataResult;

	private DefinedDataIterator(Program program, AddressSetView addrs,
			Predicate<DataType> dataTypePredicate, Predicate<Data> dataInstancePredicate) {
		this.dataTypePredicate = dataTypePredicate;
		this.dataInstancePredicate = dataInstancePredicate;

		itStack.addLast(program.getListing()
				.getDefinedData(
					(addrs == null) ? program.getMemory().getAllInitializedAddressSet() : addrs,
					true));
	}

	private DefinedDataIterator(Data singleDataInstance, Predicate<DataType> dataTypePredicate,
			Predicate<Data> dataInstancePredicate) {
		this.dataTypePredicate = dataTypePredicate;
		this.dataInstancePredicate = dataInstancePredicate;

		itStack.addLast(DataIterator.of(singleDataInstance));
	}

	@Override
	public boolean hasNext() {
		if (currentDataResult == null) {
			findNext();
		}
		return currentDataResult != null;
	}

	@Override
	public Data next() {
		if (currentDataResult == null) {
			throw new NoSuchElementException();
		}
		Data result = currentDataResult;
		currentDataResult = null;
		return result;
	}

	private DataIterator currentIt() {
		DataIterator it = null;
		while ((it = itStack.peekLast()) != null && !it.hasNext()) {
			itStack.removeLast();
		}
		return it;
	}

	private void findNext() {
		DataIterator it = null;
		while ((it = currentIt()) != null) {
			Data data = it.next();
			DataType dt = data.getBaseDataType();
			if (matchesDataTypePredicate(dt) && matchesDataInstancePredicate(data)) {
				currentDataResult = data;
				return;
			}
			if (dataTypePredicate != null && isContainerDT(dt) &&
				recursiveMatchesDataTypePredicate(dt)) {
				itStack.addLast(new DataComponentIterator(data));
			}
		}
	}

	private boolean isContainerDT(DataType dt) {
		return dt instanceof Array || dt instanceof Composite;
	}

	private boolean recursiveMatchesDataTypePredicate(DataType dt) {
		if (matchesDataTypePredicate(dt)) {
			return true;
		}
		if (dt instanceof Array) {
			Array arrayDT = (Array) dt;
			DataType elementDT = arrayDT.getDataType();
			return recursiveMatchesDataTypePredicate(elementDT);
		}
		else if (dt instanceof Structure) {
			// handle Structures and general Composite's separately so
			// we can focus on just the defined elements of a structure
			Structure comp = (Structure) dt;
			for (DataTypeComponent dtc : comp.getDefinedComponents()) {
				if (recursiveMatchesDataTypePredicate(dtc.getDataType())) {
					return true;
				}
			}
			return false;
		}
		else if (dt instanceof Composite) {
			Composite comp = (Composite) dt;
			for (DataTypeComponent dtc : comp.getComponents()) {
				if (recursiveMatchesDataTypePredicate(dtc.getDataType())) {
					return true;
				}
			}
			return false;
		}
		else if (dt instanceof TypeDef) {
			TypeDef tdDT = (TypeDef) dt;
			return recursiveMatchesDataTypePredicate(tdDT.getBaseDataType());
		}
		return false;
	}

	private boolean matchesDataTypePredicate(DataType dt) {
		return dataTypePredicate == null || dataTypePredicate.test(dt);
	}

	private boolean matchesDataInstancePredicate(Data data) {
		return dataInstancePredicate == null || dataInstancePredicate.test(data);
	}

	private static class DataComponentIterator implements DataIterator {
		private Data data;
		private int currentIndex;
		private int elementCount;

		public DataComponentIterator(Data data) {
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
