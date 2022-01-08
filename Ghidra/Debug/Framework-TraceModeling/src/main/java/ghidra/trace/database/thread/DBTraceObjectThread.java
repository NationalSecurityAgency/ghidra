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

import com.google.common.collect.Range;

import ghidra.dbg.target.TargetObject;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceThreadChangeType;
import ghidra.trace.model.target.annot.TraceObjectInterfaceUtils;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceChangeType;
import ghidra.util.LockHold;
import ghidra.util.exception.DuplicateNameException;

public class DBTraceObjectThread implements TraceObjectThread, DBTraceObjectInterface {

	protected class ThreadChangeTranslator extends Translator<TraceThread> {
		protected ThreadChangeTranslator(DBTraceObject object, TraceThread iface) {
			super(null, object, iface);
		}

		@Override
		protected TraceChangeType<TraceThread, Void> getAddedType() {
			return TraceThreadChangeType.ADDED;
		}

		@Override
		protected TraceChangeType<TraceThread, Range<Long>> getLifespanChangedType() {
			return TraceThreadChangeType.LIFESPAN_CHANGED;
		}

		@Override
		protected TraceChangeType<TraceThread, Void> getChangedType() {
			return TraceThreadChangeType.CHANGED;
		}

		@Override
		protected boolean appliesToKey(String key) {
			return KEY_COMMENT.equals(key) ||
				TargetObject.DISPLAY_ATTRIBUTE_NAME.equals(key);
		}

		@Override
		protected TraceChangeType<TraceThread, Void> getDeletedType() {
			return TraceThreadChangeType.DELETED;
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
	public void setName(String name) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(getLifespan(), TargetObject.DISPLAY_ATTRIBUTE_NAME, name);
		}
	}

	@Override
	public void setCreationSnap(long creationSnap) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setLifespan(DBTraceUtils.toRange(creationSnap, getDestructionSnap()));
		}
	}

	@Override
	public long getCreationSnap() {
		return object.getMinSnap();
	}

	@Override
	public void setDestructionSnap(long destructionSnap) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setLifespan(DBTraceUtils.toRange(getCreationSnap(), destructionSnap));
		}
	}

	@Override
	public long getDestructionSnap() {
		return object.getMaxSnap();
	}

	@Override
	public void setLifespan(Range<Long> lifespan) throws DuplicateNameException {
		TraceObjectInterfaceUtils.setLifespan(TraceObjectThread.class, object, lifespan);
	}

	@Override
	public Range<Long> getLifespan() {
		return object.getLifespan();
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
		object.deleteTree();
	}

	@Override
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		return translator.translate(rec);
	}
}
