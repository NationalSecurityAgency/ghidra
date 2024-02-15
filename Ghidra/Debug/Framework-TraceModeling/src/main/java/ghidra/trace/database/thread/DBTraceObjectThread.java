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

import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.annot.TraceObjectInterfaceUtils;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.*;
import ghidra.util.LockHold;
import ghidra.util.exception.DuplicateNameException;

public class DBTraceObjectThread implements TraceObjectThread, DBTraceObjectInterface {

	protected class ThreadChangeTranslator extends Translator<TraceThread> {
		private static final Map<TargetObjectSchema, Set<String>> KEYS_BY_SCHEMA =
			new WeakHashMap<>();

		private final Set<String> keys;

		protected ThreadChangeTranslator(DBTraceObject object, TraceThread iface) {
			super(null, object, iface);
			TargetObjectSchema schema = object.getTargetSchema();
			synchronized (KEYS_BY_SCHEMA) {
				keys = KEYS_BY_SCHEMA.computeIfAbsent(schema, s -> Set.of(
					s.checkAliasedAttribute(KEY_COMMENT),
					s.checkAliasedAttribute(TargetObject.DISPLAY_ATTRIBUTE_NAME)));
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

	public DBTraceObjectThread(DBTraceObject object) {
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
	public String getName() {
		return TraceObjectInterfaceUtils.getValue(object, getCreationSnap(),
			TargetObject.DISPLAY_ATTRIBUTE_NAME, String.class, "");
	}

	@Override
	public void setName(Lifespan lifespan, String name) {
		object.setValue(lifespan, TargetObject.DISPLAY_ATTRIBUTE_NAME, name);
	}

	@Override
	public void setName(String name) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setName(computeSpan(), name);
		}
	}

	@Override
	public void setCreationSnap(long creationSnap) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setLifespan(Lifespan.span(creationSnap, getDestructionSnap()));
		}
	}

	@Override
	public long getCreationSnap() {
		return computeMinSnap();
	}

	@Override
	public void setDestructionSnap(long destructionSnap) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setLifespan(Lifespan.span(getCreationSnap(), destructionSnap));
		}
	}

	@Override
	public long getDestructionSnap() {
		return computeMaxSnap();
	}

	@Override
	public void setLifespan(Lifespan lifespan) throws DuplicateNameException {
		TraceObjectInterfaceUtils.setLifespan(TraceObjectThread.class, object, lifespan);
	}

	@Override
	public Lifespan getLifespan() {
		return computeSpan();
	}

	@Override
	public void setComment(String comment) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(getLifespan(), KEY_COMMENT, comment);
		}
	}

	@Override
	public String getComment() {
		return TraceObjectInterfaceUtils.getValue(object, getCreationSnap(), KEY_COMMENT,
			String.class, "");
	}

	@Override
	public void delete() {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.removeTree(computeSpan());
		}
	}

	@Override
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		return translator.translate(rec);
	}
}
