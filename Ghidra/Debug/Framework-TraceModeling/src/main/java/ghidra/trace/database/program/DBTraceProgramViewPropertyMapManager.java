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
package ghidra.trace.database.program;

import java.util.Iterator;

import ghidra.program.model.address.*;
import ghidra.program.model.util.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.property.TracePropertyMap;
import ghidra.util.LockHold;
import ghidra.util.Saveable;
import ghidra.util.exception.*;
import ghidra.util.map.TypeMismatchException;
import ghidra.util.task.TaskMonitor;

public class DBTraceProgramViewPropertyMapManager implements PropertyMapManager {
	protected final DBTraceProgramView program;

	protected abstract class AbstractDBTraceProgramViewPropertyMap<T> implements PropertyMap<T> {
		protected final TracePropertyMap<T> map;
		protected final String name;

		public AbstractDBTraceProgramViewPropertyMap(TracePropertyMap<T> map, String name) {
			this.map = map;
			this.name = name;
		}

		@Override
		public String getName() {
			return name;
		}

		protected AddressSetView getAddressSetView() {
			return map.getAddressSetView(Lifespan.at(program.snap));
		}

		@Override
		public boolean intersects(Address start, Address end) {
			return getAddressSetView().intersects(start, end);
		}

		@Override
		public boolean intersects(AddressSetView set) {
			return getAddressSetView().intersects(set);
		}

		@Override
		public boolean removeRange(Address start, Address end) {
			return map.clear(Lifespan.at(program.snap), new AddressRangeImpl(start, end));
		}
	
		@Override
		public boolean remove(Address addr) {
			return removeRange(addr, addr);
		}

		@Override
		public boolean hasProperty(Address addr) {
			return intersects(addr, addr);
		}

		@Override
		public T get(Address addr) {
			return map.get(program.snap, addr);
		}

		@Override
		public Address getNextPropertyAddress(Address addr) {
			Address next = addr.next();
			if (next == null) {
				return null;
			}
			AddressRangeIterator it = getAddressSetView().getAddressRanges(next, true);
			if (!it.hasNext()) {
				return null;
			}
			AddressRange range = it.next();
			if (!range.contains(next)) {
				return next;
			}
			return range.getMinAddress();
		}

		@Override
		public Address getPreviousPropertyAddress(Address addr) {
			Address prev = addr.previous();
			if (prev == null) {
				return null;
			}
			AddressRangeIterator it = getAddressSetView().getAddressRanges(prev, false);
			if (!it.hasNext()) {
				return null;
			}
			AddressRange range = it.next();
			if (!range.contains(prev)) {
				return prev;
			}
			return range.getMaxAddress();
		}

		@Override
		public Address getFirstPropertyAddress() {
			return getAddressSetView().getMinAddress();
		}

		@Override
		public Address getLastPropertyAddress() {
			return getAddressSetView().getMaxAddress();
		}

		@Override
		public int getSize() {
			return (int) getAddressSetView().getNumAddresses();
		}

		@Override
		public AddressIterator getPropertyIterator(Address start, Address end) {
			return getPropertyIterator(start, end, true);
		}

		@Override
		public AddressIterator getPropertyIterator(Address start, Address end, boolean forward) {
			return getAddressSetView().intersectRange(start, end).getAddresses(forward);
		}

		@Override
		public AddressIterator getPropertyIterator() {
			return getAddressSetView().getAddresses(true);
		}

		@Override
		public AddressIterator getPropertyIterator(AddressSetView asv) {
			return getPropertyIterator(asv, true);
		}

		@Override
		public AddressIterator getPropertyIterator(AddressSetView asv, boolean forward) {
			return getAddressSetView().intersect(asv).getAddresses(forward);
		}

		@Override
		public AddressIterator getPropertyIterator(Address start, boolean forward) {
			return getAddressSetView().getAddresses(start, forward);
		}

		@Override
		public void moveRange(Address start, Address end, Address newStart) {
			throw new UnsupportedOperationException();
		}
	}

	protected class DBTraceProgramViewIntPropertyMap
			extends AbstractDBTraceProgramViewPropertyMap<Integer> implements IntPropertyMap {

		public DBTraceProgramViewIntPropertyMap(TracePropertyMap<Integer> map, String name) {
			super(map, name);
		}

		@Override
		public void add(Address addr, int value) {
			map.set(Lifespan.nowOnMaybeScratch(program.snap), addr, value);
		}

		@Override
		public int getInt(Address addr) throws NoValueException {
			Integer value = get(addr);
			if (value == null) {
				throw new NoValueException();
			}
			return value;
		}
	}

	protected class DBTraceProgramViewLongPropertyMap
			extends AbstractDBTraceProgramViewPropertyMap<Long> implements LongPropertyMap {

		public DBTraceProgramViewLongPropertyMap(TracePropertyMap<Long> map, String name) {
			super(map, name);
		}

		@Override
		public void add(Address addr, long value) {
			map.set(Lifespan.nowOnMaybeScratch(program.snap), addr, value);
		}

		@Override
		public long getLong(Address addr) throws NoValueException {
			Long value = get(addr);
			if (value == null) {
				throw new NoValueException();
			}
			return value;
		}
	}

	protected class DBTraceProgramViewStringPropertyMap
			extends AbstractDBTraceProgramViewPropertyMap<String> implements StringPropertyMap {

		public DBTraceProgramViewStringPropertyMap(TracePropertyMap<String> map, String name) {
			super(map, name);
		}

		@Override
		public void add(Address addr, String value) {
			map.set(Lifespan.nowOnMaybeScratch(program.snap), addr, value);
		}

		@Override
		public String getString(Address addr) {
			return get(addr);
		}
	}

	protected class DBTraceProgramViewObjectPropertyMap<T extends Saveable>
			extends AbstractDBTraceProgramViewPropertyMap<T> implements ObjectPropertyMap<T> {

		// TODO: Handle case where specific Saveable implementation class is missing

		public DBTraceProgramViewObjectPropertyMap(TracePropertyMap<T> map, String name) {
			super(map, name);
		}

		@Override
		public void add(Address addr, Saveable value) {
			map.set(Lifespan.nowOnMaybeScratch(program.snap), addr,
				map.getValueClass().cast(value));
		}

		@Override
		public Class<T> getValueClass() {
			return map.getValueClass();
		}
	}

	protected class DBTraceProgramViewVoidPropertyMap
			extends AbstractDBTraceProgramViewPropertyMap<Boolean> implements VoidPropertyMap {

		public DBTraceProgramViewVoidPropertyMap(TracePropertyMap<Boolean> map, String name) {
			super(map, name);
		}

		@Override
		public void add(Address addr) {
			map.set(Lifespan.nowOnMaybeScratch(program.snap), addr, true);
		}
	}

	public DBTraceProgramViewPropertyMapManager(DBTraceProgramView program) {
		this.program = program;
	}

	@Override
	public IntPropertyMap createIntPropertyMap(String propertyName) throws DuplicateNameException {
		return new DBTraceProgramViewIntPropertyMap(program.trace.getAddressPropertyManager()
				.createPropertyMap(propertyName, Integer.class),
			propertyName);
	}

	@Override
	public LongPropertyMap createLongPropertyMap(String propertyName)
			throws DuplicateNameException {
		return new DBTraceProgramViewLongPropertyMap(program.trace.getAddressPropertyManager()
				.createPropertyMap(propertyName, Long.class),
			propertyName);
	}

	@Override
	public StringPropertyMap createStringPropertyMap(String propertyName)
			throws DuplicateNameException {
		return new DBTraceProgramViewStringPropertyMap(program.trace.getAddressPropertyManager()
				.createPropertyMap(propertyName, String.class),
			propertyName);
	}

	@Override
	public <T extends Saveable> ObjectPropertyMap<T> createObjectPropertyMap(String propertyName,
			Class<T> objectClass) throws DuplicateNameException {
		return new DBTraceProgramViewObjectPropertyMap<>(program.trace.getAddressPropertyManager()
				.createPropertyMap(propertyName, objectClass),
			propertyName);
	}

	@Override
	public VoidPropertyMap createVoidPropertyMap(String propertyName)
			throws DuplicateNameException {
		return new DBTraceProgramViewVoidPropertyMap(program.trace.getAddressPropertyManager()
				.createPropertyMap(propertyName, Boolean.class),
			propertyName);
	}

	@Override
	@SuppressWarnings("unchecked")
	public PropertyMap<?> getPropertyMap(String propertyName) {
		TracePropertyMap<?> map =
			program.trace.getAddressPropertyManager().getPropertyMap(propertyName);
		if (map == null) {
			return null;
		}
		Class<?> cls = map.getValueClass();
		if (cls == Integer.class) {
			return new DBTraceProgramViewIntPropertyMap((TracePropertyMap<Integer>) map,
				propertyName);
		}
		if (cls == Long.class) {
			return new DBTraceProgramViewLongPropertyMap((TracePropertyMap<Long>) map,
				propertyName);
		}
		if (cls == String.class) {
			return new DBTraceProgramViewStringPropertyMap((TracePropertyMap<String>) map,
				propertyName);
		}
		if (cls == Void.class) {
			return new DBTraceProgramViewVoidPropertyMap((TracePropertyMap<Boolean>) map,
				propertyName);
		}
		if (Saveable.class.isAssignableFrom(cls)) {
			return new DBTraceProgramViewObjectPropertyMap<>(
				(TracePropertyMap<? extends Saveable>) map, propertyName);
		}
		// TODO: Handle unsupported map (simiar to UnsupportedMapDB) 
		throw new AssertionError("Where did this property map type come from? " + cls);
	}

	@Override
	public IntPropertyMap getIntPropertyMap(String propertyName) {
		TracePropertyMap<Integer> map = program.trace.getAddressPropertyManager()
				.getPropertyMap(propertyName, Integer.class);
		return map == null ? null : new DBTraceProgramViewIntPropertyMap(map, propertyName);
	}

	@Override
	public LongPropertyMap getLongPropertyMap(String propertyName) {
		TracePropertyMap<Long> map = program.trace.getAddressPropertyManager()
				.getPropertyMap(propertyName, Long.class);
		return map == null ? null : new DBTraceProgramViewLongPropertyMap(map, propertyName);
	}

	@Override
	public StringPropertyMap getStringPropertyMap(String propertyName) {
		TracePropertyMap<String> map = program.trace.getAddressPropertyManager()
				.getPropertyMap(propertyName, String.class);
		return map == null ? null : new DBTraceProgramViewStringPropertyMap(map, propertyName);
	}

	@Override
	@SuppressWarnings("unchecked")
	public ObjectPropertyMap<? extends Saveable> getObjectPropertyMap(String propertyName) {
		TracePropertyMap<?> map =
			program.trace.getAddressPropertyManager().getPropertyMap(propertyName);
		if (map == null) {
			return null;
		}
		if (!Saveable.class.isAssignableFrom(map.getValueClass())) {
			throw new TypeMismatchException("Property " + propertyName + " is not object type");
		}
		return new DBTraceProgramViewObjectPropertyMap<>((TracePropertyMap<? extends Saveable>) map,
			propertyName);
	}

	@Override
	public VoidPropertyMap getVoidPropertyMap(String propertyName) {
		TracePropertyMap<Boolean> map = program.trace.getAddressPropertyManager()
				.getPropertyMap(propertyName, Boolean.class);
		return map == null ? null : new DBTraceProgramViewVoidPropertyMap(map, propertyName);
	}

	@Override
	public boolean removePropertyMap(String propertyName) {
		// It would delete for entire trace, not just this view
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<String> propertyManagers() {
		return program.trace.getAddressPropertyManager().getAllProperties().keySet().iterator();
	}

	protected void removeAll(Lifespan span, AddressRange range) {
		try (LockHold hold = program.trace.lockWrite()) {
			for (TracePropertyMap<?> map : program.trace.getAddressPropertyManager()
					.getAllProperties()
					.values()) {
				map.clear(span, range);
			}
		}
	}

	@Override
	public void removeAll(Address addr) {
		removeAll(Lifespan.nowOnMaybeScratch(program.snap), new AddressRangeImpl(addr, addr));
	}

	@Override
	public void removeAll(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		removeAll(Lifespan.nowOnMaybeScratch(program.snap),
			new AddressRangeImpl(startAddr, endAddr));
	}
}
