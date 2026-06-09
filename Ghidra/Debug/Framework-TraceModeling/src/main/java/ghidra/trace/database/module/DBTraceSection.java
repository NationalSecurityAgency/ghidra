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
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.info.TraceObjectInterfaceUtils;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.util.*;
import ghidra.util.LockHold;

public class DBTraceSection implements TraceSection, DBTraceObjectInterface {

	protected class SectionTranslator extends Translator<TraceSection> {
		private static final Map<TraceObjectSchema, Set<String>> KEYS_BY_SCHEMA =
			new WeakHashMap<>();

		private final Set<String> keys;

		protected SectionTranslator(DBTraceObject object, TraceSection iface) {
			super(KEY_RANGE, object, iface);
			TraceObjectSchema schema = object.getSchema();
			synchronized (KEYS_BY_SCHEMA) {
				keys = KEYS_BY_SCHEMA.computeIfAbsent(schema, s -> Set.of(
					s.checkAliasedAttribute(KEY_RANGE),
					s.checkAliasedAttribute(KEY_DISPLAY)));
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

	public DBTraceSection(DBTraceObject object) {
		this.object = object;

		translator = new SectionTranslator(object, this);
	}

	@Override
	public Trace getTrace() {
		return object.getTrace();
	}

	@Override
	public TraceModule getModule() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return object.queryCanonicalAncestorsInterface(TraceModule.class)
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
		object.setValue(lifespan, KEY_DISPLAY, name);
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
		return TraceObjectInterfaceUtils.getValue(object, snap, KEY_DISPLAY, String.class, index);
	}

	@Override
	public void setRange(Lifespan lifespan, AddressRange range) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(lifespan, KEY_RANGE, range);
		}
	}

	@Override
	public AddressRange getRange(long snap) {
		try (LockHold hold = object.getTrace().lockRead()) {
			return TraceObjectInterfaceUtils.getValue(object, snap, KEY_RANGE,
				AddressRange.class, null);
		}
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
	public TraceObject getObject() {
		return object;
	}

	@Override
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		return translator.translate(rec);
	}
}
