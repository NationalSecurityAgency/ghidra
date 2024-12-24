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
import ghidra.trace.model.modules.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInterfaceUtils;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.path.PathFilter.Align;
import ghidra.trace.model.target.path.PathMatcher;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.util.*;
import ghidra.util.LockHold;
import ghidra.util.exception.DuplicateNameException;

public class DBTraceObjectModule implements TraceObjectModule, DBTraceObjectInterface {

	protected class ModuleChangeTranslator extends Translator<TraceModule> {
		private static final Map<TraceObjectSchema, Set<String>> KEYS_BY_SCHEMA =
			new WeakHashMap<>();

		private final Set<String> keys;

		protected ModuleChangeTranslator(DBTraceObject object, TraceModule iface) {
			super(TraceObjectModule.KEY_RANGE, object, iface);
			TraceObjectSchema schema = object.getSchema();
			synchronized (KEYS_BY_SCHEMA) {
				keys = KEYS_BY_SCHEMA.computeIfAbsent(schema, s -> Set.of(
					s.checkAliasedAttribute(TraceObjectModule.KEY_RANGE),
					s.checkAliasedAttribute(TraceObjectInterface.KEY_DISPLAY)));
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

	// Keep copies here for when the object gets invalidated
	private AddressRange range;
	private Lifespan lifespan;

	public DBTraceObjectModule(DBTraceObject object) {
		this.object = object;

		translator = new ModuleChangeTranslator(object, this);
	}

	@Override
	public Trace getTrace() {
		return object.getTrace();
	}

	@Override
	public TraceSection addSection(String sectionPath, String sectionName, AddressRange range)
			throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			DBTraceObjectManager manager = object.getManager();
			KeyPath sectionKeyList = KeyPath.parse(sectionPath);
			if (!object.getCanonicalPath().isAncestor(sectionKeyList)) {
				throw new IllegalArgumentException(
					"Section path must be a successor of this module's path");
			}
			return manager.addSection(sectionPath, sectionName, getLifespan(), range);
		}
	}

	@Override
	public String getPath() {
		return object.getCanonicalPath().toString();
	}

	@Override
	public void setName(Lifespan lifespan, String name) {
		object.setValue(lifespan, TraceObjectModule.KEY_MODULE_NAME, name);
	}

	@Override
	public void setName(String name) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setName(computeSpan(), name);
		}
	}

	@Override
	public String getName() {
		return TraceObjectInterfaceUtils.getValue(object, getLoadedSnap(),
			TraceObjectModule.KEY_MODULE_NAME, String.class, "");
	}

	@Override
	public void setRange(Lifespan lifespan, AddressRange range) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(lifespan, TraceObjectModule.KEY_RANGE, range);
			this.range = range;
		}
	}

	@Override
	public void setRange(AddressRange range) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(computeSpan(), range);
		}
	}

	@Override
	public AddressRange getRange() {
		try (LockHold hold = object.getTrace().lockRead()) {
			if (object.getLife().isEmpty()) {
				return range;
			}
			return range = TraceObjectInterfaceUtils.getValue(object, getLoadedSnap(),
				TraceObjectModule.KEY_RANGE, AddressRange.class, range);
		}
	}

	@Override
	public void setBase(Address base) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(DBTraceUtils.toRange(base, getMaxAddress()));
		}
	}

	@Override
	public Address getBase() {
		AddressRange range = getRange();
		return range == null ? null : range.getMinAddress();
	}

	@Override
	public void setMaxAddress(Address max) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(DBTraceUtils.toRange(getBase(), max));
		}
	}

	@Override
	public Address getMaxAddress() {
		AddressRange range = getRange();
		return range == null ? null : range.getMaxAddress();
	}

	@Override
	public void setLength(long length) throws AddressOverflowException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(new AddressRangeImpl(getBase(), length));
		}
	}

	@Override
	public long getLength() {
		return getRange().getLength();
	}

	@Override
	public void setLifespan(Lifespan lifespan) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			TraceObjectInterfaceUtils.setLifespan(TraceObjectModule.class, object, lifespan);
			this.lifespan = lifespan;
			for (TraceObjectSection section : getSections()) {
				TraceObjectInterfaceUtils.setLifespan(TraceObjectSection.class, section.getObject(),
					lifespan);
			}
		}
	}

	@Override
	public Lifespan getLifespan() {
		try (LockHold hold = object.getTrace().lockRead()) {
			Lifespan computed = computeSpan();
			if (computed != null) {
				lifespan = computed;
			}
			return lifespan;
		}
	}

	@Override
	public void setLoadedSnap(long loadedSnap) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setLifespan(Lifespan.span(loadedSnap, getUnloadedSnap()));
		}
	}

	@Override
	public long getLoadedSnap() {
		return computeMinSnap();
	}

	@Override
	public void setUnloadedSnap(long unloadedSnap) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setLifespan(Lifespan.span(getLoadedSnap(), unloadedSnap));
		}
	}

	@Override
	public long getUnloadedSnap() {
		return computeMaxSnap();
	}

	@Override
	public Collection<? extends TraceObjectSection> getSections() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return object.querySuccessorsInterface(getLifespan(), TraceObjectSection.class, true)
					.collect(Collectors.toSet());
		}
	}

	@Override
	public TraceObjectSection getSectionByName(String sectionName) {
		PathMatcher matcher = object.getSchema().searchFor(TraceObjectSection.class, true);
		PathMatcher applied = matcher.applyKeys(Align.LEFT, List.of(sectionName));
		return object.getSuccessors(getLifespan(), applied)
				.map(p -> p.getDestination(object).queryInterface(TraceObjectSection.class))
				.findAny()
				.orElse(null);
	}

	@Override
	public void delete() {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.removeTree(computeSpan());
		}
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
