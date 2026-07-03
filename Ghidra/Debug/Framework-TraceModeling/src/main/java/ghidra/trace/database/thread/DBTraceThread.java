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
package ghidra.trace.database.thread;

import java.util.*;

import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.info.TraceObjectInterfaceUtils;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.*;
import ghidra.util.LockHold;

public class DBTraceThread implements TraceThread, DBTraceObjectInterface {

	protected class ThreadChangeTranslator extends Translator<TraceThread> {
		private static final Map<TraceObjectSchema, Set<String>> KEYS_BY_SCHEMA =
			new WeakHashMap<>();

		private final Set<String> keys;

		protected ThreadChangeTranslator(DBTraceObject object, TraceThread iface) {
			super(null, object, iface);
			TraceObjectSchema schema = object.getSchema();
			synchronized (KEYS_BY_SCHEMA) {
				keys = KEYS_BY_SCHEMA.computeIfAbsent(schema, s -> Set.of(
					s.checkAliasedAttribute(KEY_COMMENT),
					s.checkAliasedAttribute(KEY_DISPLAY)));
			}
		}

		@Override
		protected TraceEvent<TraceThread, Void> getAddedType() {
			return TraceEvents.THREAD_ADDED;
		}

		@Override
		protected TraceEvent<TraceThread, Lifespan> getLifespanChangedType() {
			return TraceEvents.THREAD_LIFESPAN_CHANGED;
		}

		@Override
		protected TraceEvent<TraceThread, Void> getChangedType() {
			return TraceEvents.THREAD_CHANGED;
		}

		@Override
		protected boolean appliesToKey(String key) {
			return keys.contains(key);
		}

		@Override
		protected TraceEvent<TraceThread, Void> getDeletedType() {
			return TraceEvents.THREAD_DELETED;
		}
	}

	private final DBTraceObject object;
	private final ThreadChangeTranslator translator;

	public DBTraceThread(DBTraceObject object) {
		this.object = object;

		translator = new ThreadChangeTranslator(object, this);
	}

	@Override
	public DBTraceObject getObject() {
		return object;
	}

	@Override
	public Trace getTrace() {
		return object.getTrace();
	}

	@Override
	public long getKey() {
		return object.getKey();
	}

	@Override
	public String getPath() {
		return object.getCanonicalPath().toString();
	}

	@Override
	public String getName(long snap) {
		return TraceObjectInterfaceUtils.getValue(object, snap, KEY_DISPLAY, String.class, "");
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
	public void setComment(long snap, String comment) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(Lifespan.nowOn(snap), KEY_COMMENT, comment);
		}
	}

	@Override
	public String getComment(long snap) {
		return TraceObjectInterfaceUtils.getValue(object, snap, KEY_COMMENT, String.class, "");
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
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		return translator.translate(rec);
	}
}
