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

import java.util.LinkedList;
import java.util.Queue;
import java.util.function.Predicate;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

/**
 * Iterator that visits each defined data instance in a Program or in the footprint of
 * a specified data element.
 * <p>
 * Data elements that are nested inside of composites or arrays are visited, not just the
 * parent/containing data element.
 */
public class DefinedDataIterator implements DataIterator {

	/**
	 * Creates a new iterator that traverses the entire Program's address space, visiting
	 * data instances that successfully match the predicate.
	 *
	 * @param program Program to search
	 * @param dataTypePredicate {@link Predicate} that tests each data instance's {@link DataType}
	 * @return new iterator
	 */
	public static DefinedDataIterator byDataType(Program program,
			Predicate<DataType> dataTypePredicate) {
		return new DefinedDataIterator(program, null,
			data -> dataTypePredicate.test(data.getBaseDataType()));
	}

	/**
	 * Creates a new iterator that traverses the entire Program's address space.
	 *
	 * @param program Ghidra {@link Program} to search
	 * @return new iterator
	 */
	public static DefinedDataIterator definedStrings(Program program) {
		return new DefinedDataIterator(program, null, data -> StringDataInstance.isString(data));
	}

	/**
	 * Creates a new iterator that traverses a portion of the Program's address space.
	 *
	 * @param program Ghidra {@link Program} to search
	 * @param addrs addresses to limit the iteration to
	 * @return new iterator
	 */
	public static DefinedDataIterator definedStrings(Program program, AddressSetView addrs) {
		return new DefinedDataIterator(program, addrs, data -> StringDataInstance.isString(data));
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
			data -> StringDataInstance.isString(data));
	}

	private Queue<Data> resultsQueue = new LinkedList<>();
	private Predicate<Data> dataInstancePredicate;
	private DataIterator definedDataIterator;

	private DefinedDataIterator(Program program, AddressSetView addrs,
			Predicate<Data> dataInstancePredicate) {
		this.dataInstancePredicate = dataInstancePredicate;
		this.definedDataIterator = program.getListing().getDefinedData(
			(addrs == null) ? program.getMemory().getAllInitializedAddressSet() : addrs, true);
	}

	private DefinedDataIterator(Data singleDataInstance, Predicate<Data> dataInstancePredicate) {
		this.dataInstancePredicate = dataInstancePredicate;
		this.definedDataIterator = DataIterator.EMPTY;
		processDataInstance(singleDataInstance);
	}

	@Override
	public boolean hasNext() {
		if (resultsQueue.isEmpty()) {
			findNext();
		}
		return !resultsQueue.isEmpty();
	}

	@Override
	public Data next() {
		if (hasNext()) {
			return resultsQueue.remove();
		}
		return null;
	}

	private void findNext() {
		while (definedDataIterator.hasNext() && resultsQueue.isEmpty()) {
			Data nextData = definedDataIterator.next();
			processDataInstance(nextData);
		}
	}

	private void processDataInstance(Data data) {
		if (dataInstancePredicate.test(data)) {
			resultsQueue.add(data);
			return;
		}
		DataType dt = data.getBaseDataType();
		if (dt instanceof Composite || isIterableArray(dt)) {
			for (int compNum = 0, compCount =
				data.getNumComponents(); compNum < compCount; compNum++) {
				Data componentData = data.getComponent(compNum);
				processDataInstance(componentData);
			}
		}
	}

	private boolean isIterableArray(DataType dataType) {
		if (dataType instanceof Array) {
			DataType elementDT = ((Array) dataType).getDataType();
			if (elementDT instanceof TypeDef) {
				elementDT = ((TypeDef) elementDT).getBaseDataType();
			}
			return (elementDT instanceof Array) || (elementDT instanceof Composite) ||
				(elementDT instanceof AbstractStringDataType);
		}
		return false;
	}
}
