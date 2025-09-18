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
package ghidra.trace.database.module;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.program.model.address.*;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.target.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.info.TraceObjectInterfaceUtils;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.path.PathFilter;
import ghidra.trace.model.target.path.PathFilter.Align;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.util.*;
import ghidra.util.LockHold;
import ghidra.util.exception.DuplicateNameException;

public class DBTraceModule implements TraceModule, DBTraceObjectInterface {

	protected class ModuleChangeTranslator extends Translator<TraceModule> {
		private static final Map<TraceObjectSchema, Set<String>> KEYS_BY_SCHEMA =
			new WeakHashMap<>();

		private final Set<String> keys;

		protected ModuleChangeTranslator(DBTraceObject object, TraceModule iface) {
			super(KEY_RANGE, object, iface);
			TraceObjectSchema schema = object.getSchema();
			synchronized (KEYS_BY_SCHEMA) {
				keys = KEYS_BY_SCHEMA.computeIfAbsent(schema, s -> Set.of(
					s.checkAliasedAttribute(KEY_RANGE),
					s.checkAliasedAttribute(KEY_DISPLAY)));
			}
		}

		@Override
		protected TraceEvent<TraceModule, Void> getAddedType() {
			return TraceEvents.MODULE_ADDED;
		}

		@Override
		protected TraceEvent<TraceModule, Lifespan> getLifespanChangedType() {
			return TraceEvents.MODULE_LIFESPAN_CHANGED;
		}

		@Override
		protected TraceEvent<TraceModule, Void> getChangedType() {
			return TraceEvents.MODULE_CHANGED;
		}

		@Override
		protected boolean appliesToKey(String key) {
			return keys.contains(key);
		}

		@Override
		protected TraceEvent<TraceModule, Void> getDeletedType() {
			return TraceEvents.MODULE_DELETED;
		}
	}

	private final DBTraceObject object;
	private final ModuleChangeTranslator translator;

	public DBTraceModule(DBTraceObject object) {
		this.object = object;

		translator = new ModuleChangeTranslator(object, this);
	}

	@Override
	public Trace getTrace() {
		return object.getTrace();
	}

	@Override
	public TraceSection addSection(long snap, String sectionPath, String sectionName,
			AddressRange range) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			DBTraceObjectManager manager = object.getManager();
			KeyPath sectionKeyList = KeyPath.parse(sectionPath);
			if (!object.getCanonicalPath().isAncestor(sectionKeyList)) {
				throw new IllegalArgumentException(
					"Section path must be a successor of this module's path");
			}
			return manager.addSection(sectionPath, sectionName, Lifespan.nowOn(snap), range);
		}
	}

	@Override
	public String getPath() {
		return object.getCanonicalPath().toString();
	}

	@Override
	public void setName(Lifespan lifespan, String name) {
		object.setValue(lifespan, KEY_MODULE_NAME, name);
	}

	@Override
	public void setName(long snap, String name) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setName(Lifespan.nowOn(snap), name);
		}
	}

	@Override
	public String getName(long snap) {
		String key = object.getCanonicalPath().key();
		String index = KeyPath.parseIfIndex(key);
		return TraceObjectInterfaceUtils.getValue(object, snap, KEY_MODULE_NAME, String.class,
			index);
	}

	@Override
	public void setRange(Lifespan lifespan, AddressRange range) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(lifespan, KEY_RANGE, range);
		}
	}

	@Override
	public void setRange(long snap, AddressRange range) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(Lifespan.nowOn(snap), range);
		}
	}

	@Override
	public AddressRange getRange(long snap) {
		try (LockHold hold = object.getTrace().lockRead()) {
			return TraceObjectInterfaceUtils.getValue(object, snap, KEY_RANGE, AddressRange.class,
				null);
		}
	}

	@Override
	public void setBase(long snap, Address base) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(snap, DBTraceUtils.toRange(base, getMaxAddress(snap)));
		}
	}

	@Override
	public Address getBase(long snap) {
		AddressRange range = getRange(snap);
		return range == null ? null : range.getMinAddress();
	}

	@Override
	public void setMaxAddress(long snap, Address max) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(snap, DBTraceUtils.toRange(getBase(snap), max));
		}
	}

	@Override
	public Address getMaxAddress(long snap) {
		AddressRange range = getRange(snap);
		return range == null ? null : range.getMaxAddress();
	}

	@Override
	public void setLength(long snap, long length) throws AddressOverflowException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(snap, new AddressRangeImpl(getBase(snap), length));
		}
	}

	@Override
	public long getLength(long snap) {
		AddressRange range = getRange(snap);
		return range == null ? 0 : range.getLength();
	}

	@Override
	public Collection<? extends TraceSection> getSections(long snap) {
		try (LockHold hold = object.getTrace().lockRead()) {
			return object
					.querySuccessorsInterface(Lifespan.at(snap), TraceSection.class, true)
					.collect(Collectors.toSet());
		}
	}

	@Override
	public Collection<? extends TraceSection> getAllSections() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return object
					.querySuccessorsInterface(Lifespan.ALL, TraceSection.class, true)
					.collect(Collectors.toSet());
		}
	}

	@Override
	public TraceSection getSectionByName(long snap, String sectionName) {
		PathFilter filter = object.getSchema().searchFor(TraceSection.class, true);
		PathFilter applied = filter.applyKeys(Align.LEFT, List.of(sectionName));
		return object.getSuccessors(Lifespan.at(snap), applied)
				.map(p -> p.getDestination(object).queryInterface(TraceSection.class))
				.findAny()
				.orElse(null);
	}

	@Override
	public void delete() {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.removeTree(Lifespan.ALL);
		}
	}

	@Override
	public void remove(long snap) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.removeTree(Lifespan.nowOn(snap));
		}
	}

	@Override
	public boolean isValid(long snap) {
		return object.isAlive(snap);
	}

	@Override
	public boolean isAlive(Lifespan span) {
		return object.isAlive(span);
	}

	@Override
	public TraceObject getObject() {
		return object;
	}

	@Override
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		return translator.translate(rec);
	}
}
