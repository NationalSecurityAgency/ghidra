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
package ghidra.trace.database.listing;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.util.LockHold;
import ghidra.util.Msg;

public interface DBTraceDefinedDataAdapter extends DBTraceDataAdapter {

	@Override
	default boolean isDefined() {
		// NOTE: from DataDB, it seems this is true even if the dataType is Undefined
		// It just cannot by DataType.DEFAULT
		return true;
	}

	/**
	 * TODO: Document me
	 * 
	 * Note this will always be called with the write lock
	 * 
	 * @return the new or existing component cache
	 */
	AbstractDBTraceDataComponent[] doGetComponentCache();

	@Override
	default int getNumComponents() {
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().readLock())) {
			if (getLength() < getDataType().getLength()) {
				return -1;
			}
			DataType baseDataType = getBaseDataType();
			if (baseDataType instanceof Composite) {
				return ((Composite) baseDataType).getNumComponents();
			}
			if (baseDataType instanceof Array) {
				return ((Array) baseDataType).getNumElements();
			}
			if (baseDataType instanceof DynamicDataType) {
				try {
					return ((DynamicDataType) baseDataType).getNumComponents(this);
				}
				catch (Exception e) {
					// TODO: Why does the original use Throwable?
					return 0;
				}
			}
			return 0;
		}
	}

	@Override
	DBTraceData getRoot();

	@Override
	DBTraceDefinedDataAdapter getParent();

	StringBuilder getPathName(StringBuilder builder, boolean includeRootSymbol);

	@Override
	default DBTraceDefinedDataAdapter getComponent(int index) {
		// We may write to the cache
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().writeLock())) {
			if (index < 0 || index >= getNumComponents()) {
				return null;
			}

			DBTraceDefinedDataAdapter[] cache = doGetComponentCache();
			if (cache[index] != null) {
				return cache[index];
			}

			DataType baseDataType = getBaseDataType();
			if (baseDataType instanceof Array) {
				Array array = (Array) baseDataType;
				int elementLength = array.getElementLength();
				Address componentAddress = getAddress().add(index * elementLength);
				return cache[index] = new DBTraceDataArrayElementComponent(getRoot(), this, index,
					componentAddress, array.getDataType(), elementLength);
			}
			if (baseDataType instanceof Composite) {
				Composite composite = (Composite) baseDataType;
				DataTypeComponent dtc = composite.getComponent(index);
				Address componentAddress = getAddress().add(dtc.getOffset());
				return cache[index] =
					new DBTraceDataCompositeFieldComponent(getRoot(), this, componentAddress, dtc);
			}
			if (baseDataType instanceof DynamicDataType) {
				DynamicDataType dynamic = (DynamicDataType) baseDataType;
				DataTypeComponent dtc = dynamic.getComponent(index, this);
				Address componentAddress = getAddress().add(dtc.getOffset());
				return cache[index] =
					new DBTraceDataCompositeFieldComponent(getRoot(), this, componentAddress, dtc);
			}
			Msg.error(this,
				"Unsupported composite data type class: " + baseDataType.getClass().getName());
			return null;
		}
	}

	@Override
	default DBTraceDefinedDataAdapter getComponentAt(int offset) {
		// We may write to the cache
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().writeLock())) {
			if (offset < 0 || offset >= getLength()) {
				return null;
			}

			DataType baseDataType = getBaseDataType();
			if (baseDataType instanceof Array) {
				Array array = (Array) baseDataType;
				int elementLength = array.getElementLength();
				int index = offset / elementLength;
				return getComponent(index);
			}
			if (baseDataType instanceof Structure) {
				Structure structure = (Structure) baseDataType;
				DataTypeComponent dtc = structure.getComponentAt(offset);
				return dtc == null ? null : getComponent(dtc.getOrdinal());
			}
			if (baseDataType instanceof Union) {
				return null; // Use getComponentsContaining
			}
			if (baseDataType instanceof DynamicDataType) {
				DynamicDataType dynamic = (DynamicDataType) baseDataType;
				DataTypeComponent dtc = dynamic.getComponentAt(offset, this);
				return dtc == null ? null : getComponent(dtc.getOrdinal());
			}
			return null;
		}
	}

	@Override
	default List<Data> getComponentsContaining(int offset) {
		// We may write to the cache
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().writeLock())) {
			if (offset < 0 || offset >= getLength()) {
				return null;
			}

			DataType baseDataType = getBaseDataType();
			if (baseDataType instanceof Array) {
				Array array = (Array) baseDataType;
				int elementLength = array.getElementLength();
				int index = offset / elementLength;
				return Collections.singletonList(getComponent(index));
			}
			if (baseDataType instanceof Structure) {
				Structure structure = (Structure) baseDataType;
				DataTypeComponent dtc = structure.getComponentAt(offset);
				List<Data> result = new ArrayList<>();
				// Logic handles overlapping bit fields
				// Include if offset is contained within bounds of component
				while (dtc != null && offset >= dtc.getOffset() &&
					offset <= dtc.getOffset() + dtc.getLength() - 1) {
					int ordinal = dtc.getOrdinal(); // TODO: Seems I could move this before while
					result.add(getComponent(ordinal));
					ordinal++;
					dtc = ordinal < structure.getNumComponents() ? structure.getComponent(ordinal)
							: null;
				}
				return result;
			}
			if (baseDataType instanceof Union) {
				/** NOTE: The {@link DataDB} implementation seems hasty */
				Union union = (Union) baseDataType;
				List<Data> result = new ArrayList<>();
				for (DataTypeComponent dtc : union.getComponents()) {
					if (offset < dtc.getLength()) {
						result.add(getComponent(dtc.getOrdinal()));
					}
				}
				return result;
			}
			if (baseDataType instanceof DynamicDataType) {
				DynamicDataType dynamic = (DynamicDataType) baseDataType;
				DataTypeComponent dtc = dynamic.getComponentAt(offset, this);
				return dtc == null ? Collections.emptyList()
						: Collections.singletonList(getComponent(dtc.getOrdinal()));
			}
			return Collections.emptyList();
		}
	}

	@Override
	default DBTraceDefinedDataAdapter getPrimitiveAt(int offset) {
		// We may write to the cache
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().writeLock())) {
			if (offset < 0 || offset >= getLength()) {
				return null;
			}
			DBTraceDefinedDataAdapter component = getComponentAt(offset);
			if (component == null || component == this) {
				return this;
			}
			return component.getPrimitiveAt(offset - component.getParentOffset());
		}
	}

	default DBTraceDefinedDataAdapter doGetComponent(int[] componentPath, int level) {
		if (componentPath == null || level >= componentPath.length) {
			return this;
		}
		DBTraceDefinedDataAdapter next = getComponent(componentPath[level]);
		return next == null ? null : next.doGetComponent(componentPath, level + 1);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * This implementation differs in that the path is relative to this unit, even if it is not the
	 * root. In {@link DataDB}, it appears the behavior is undefined if you call this on a non-root
	 * component.
	 */
	@Override
	default DBTraceDefinedDataAdapter getComponent(int[] componentPath) {
		// We may write to the cache
		// TODO: Consider a separate lock for the cache?
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().writeLock())) {
			return doGetComponent(componentPath, 0);
		}
	}
}
