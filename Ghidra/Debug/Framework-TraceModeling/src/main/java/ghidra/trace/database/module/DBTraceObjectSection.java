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

import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.modules.TraceObjectModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInterfaceUtils;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.util.*;
import ghidra.util.LockHold;

public class DBTraceObjectSection implements TraceObjectSection, DBTraceObjectInterface {

	protected class SectionTranslator extends Translator<TraceSection> {
		private static final Map<TraceObjectSchema, Set<String>> KEYS_BY_SCHEMA =
			new WeakHashMap<>();

		private final Set<String> keys;

		protected SectionTranslator(DBTraceObject object, TraceSection iface) {
			super(TraceObjectSection.KEY_RANGE, object, iface);
			TraceObjectSchema schema = object.getSchema();
			synchronized (KEYS_BY_SCHEMA) {
				keys = KEYS_BY_SCHEMA.computeIfAbsent(schema, s -> Set.of(
					s.checkAliasedAttribute(TraceObjectSection.KEY_RANGE),
					s.checkAliasedAttribute(TraceObjectInterface.KEY_DISPLAY)));
			}
		}

		@Override
		protected TraceEvent<TraceSection, Void> getAddedType() {
			return TraceEvents.SECTION_ADDED;
		}

		@Override
		protected TraceEvent<TraceSection, Lifespan> getLifespanChangedType() {
			return null; // it's the module's lifespan that matters.
		}

		@Override
		protected TraceEvent<TraceSection, Void> getChangedType() {
			return TraceEvents.SECTION_CHANGED;
		}

		@Override
		protected boolean appliesToKey(String key) {
			return keys.contains(key);
		}

		@Override
		protected TraceEvent<TraceSection, Void> getDeletedType() {
			return TraceEvents.SECTION_DELETED;
		}
	}

	private final DBTraceObject object;
	private final SectionTranslator translator;

	// Keep copies here for when the object gets invalidated
	private AddressRange range;

	public DBTraceObjectSection(DBTraceObject object) {
		this.object = object;

		translator = new SectionTranslator(object, this);
	}

	@Override
	public Trace getTrace() {
		return object.getTrace();
	}

	@Override
	public TraceObjectModule getModule() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return object.queryCanonicalAncestorsInterface(TraceObjectModule.class)
					.findAny()
					.orElseThrow();
		}
	}

	@Override
	public String getPath() {
		return object.getCanonicalPath().toString();
	}

	@Override
	public void setName(Lifespan lifespan, String name) {
		object.setValue(lifespan, TraceObjectInterface.KEY_DISPLAY, name);
	}

	@Override
	public void setName(String name) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setName(computeSpan(), name);
		}
	}

	@Override
	public String getName() {
		String key = object.getCanonicalPath().key();
		String index = KeyPath.parseIfIndex(key);
		return TraceObjectInterfaceUtils.getValue(object, computeMinSnap(),
			TraceObjectInterface.KEY_DISPLAY, String.class, index);
	}

	@Override
	public void setRange(Lifespan lifespan, AddressRange range) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(lifespan, TraceObjectModule.KEY_RANGE, range);
			this.range = range;
		}
	}

	@Override
	public AddressRange getRange() {
		try (LockHold hold = object.getTrace().lockRead()) {
			if (object.getLife().isEmpty()) {
				return range;
			}
			return range = TraceObjectInterfaceUtils.getValue(object, computeMinSnap(),
				TraceObjectModule.KEY_RANGE, AddressRange.class, range);
		}
	}

	@Override
	public Lifespan computeSpan() {
		Lifespan span = DBTraceObjectInterface.super.computeSpan();
		if (span != null) {
			return span;
		}
		return getModule().computeSpan();
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
