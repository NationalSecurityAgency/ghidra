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

import ghidra.dbg.target.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceSectionChangeType;
import ghidra.trace.model.modules.TraceObjectModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.annot.TraceObjectInterfaceUtils;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceChangeType;
import ghidra.util.LockHold;

public class DBTraceObjectSection implements TraceObjectSection, DBTraceObjectInterface {

	protected class SectionTranslator extends Translator<TraceSection> {
		protected SectionTranslator(DBTraceObject object, TraceSection iface) {
			super(TargetSection.RANGE_ATTRIBUTE_NAME, object, iface);
		}

		@Override
		protected TraceChangeType<TraceSection, Void> getAddedType() {
			return TraceSectionChangeType.ADDED;
		}

		@Override
		protected TraceChangeType<TraceSection, Lifespan> getLifespanChangedType() {
			return null; // it's the module's lifespan that matters.
		}

		@Override
		protected TraceChangeType<TraceSection, Void> getChangedType() {
			return TraceSectionChangeType.CHANGED;
		}

		@Override
		protected boolean appliesToKey(String key) {
			return TargetSection.RANGE_ATTRIBUTE_NAME.equals(key) ||
				TargetObject.DISPLAY_ATTRIBUTE_NAME.equals(key);
		}

		@Override
		protected TraceChangeType<TraceSection, Void> getDeletedType() {
			return TraceSectionChangeType.DELETED;
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
		object.setValue(lifespan, TargetObject.DISPLAY_ATTRIBUTE_NAME, name);
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
		String index = PathUtils.isIndex(key) ? PathUtils.parseIndex(key) : key;
		return TraceObjectInterfaceUtils.getValue(object, computeMinSnap(),
			TargetObject.DISPLAY_ATTRIBUTE_NAME, String.class, index);
	}

	@Override
	public void setRange(Lifespan lifespan, AddressRange range) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(lifespan, TargetModule.RANGE_ATTRIBUTE_NAME, range);
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
				TargetModule.RANGE_ATTRIBUTE_NAME, AddressRange.class, range);
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
