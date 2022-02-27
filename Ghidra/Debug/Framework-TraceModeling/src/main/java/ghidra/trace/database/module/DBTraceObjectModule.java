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

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import com.google.common.collect.Range;

import ghidra.dbg.target.*;
import ghidra.dbg.util.PathMatcher;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.target.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceModuleChangeType;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.annot.TraceObjectInterfaceUtils;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceChangeType;
import ghidra.util.LockHold;
import ghidra.util.exception.DuplicateNameException;

public class DBTraceObjectModule implements TraceObjectModule, DBTraceObjectInterface {

	protected class ModuleChangeTranslator extends Translator<TraceModule> {
		protected ModuleChangeTranslator(DBTraceObject object, TraceModule iface) {
			super(TargetModule.RANGE_ATTRIBUTE_NAME, object, iface);
		}

		@Override
		protected TraceChangeType<TraceModule, Void> getAddedType() {
			return TraceModuleChangeType.ADDED;
		}

		@Override
		protected TraceChangeType<TraceModule, Range<Long>> getLifespanChangedType() {
			return TraceModuleChangeType.LIFESPAN_CHANGED;
		}

		@Override
		protected TraceChangeType<TraceModule, Void> getChangedType() {
			return TraceModuleChangeType.CHANGED;
		}

		@Override
		protected boolean appliesToKey(String key) {
			return TargetModule.RANGE_ATTRIBUTE_NAME.equals(key) ||
				TargetObject.DISPLAY_ATTRIBUTE_NAME.equals(key);
		}

		@Override
		protected TraceChangeType<TraceModule, Void> getDeletedType() {
			return TraceModuleChangeType.DELETED;
		}
	}

	private final DBTraceObject object;
	private final ModuleChangeTranslator translator;

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
			List<String> sectionKeyList = PathUtils.parse(sectionPath);
			if (!PathUtils.isAncestor(object.getCanonicalPath().getKeyList(), sectionKeyList)) {
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
	public void setName(String name) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(getLifespan(), TargetObject.DISPLAY_ATTRIBUTE_NAME, name);
		}
	}

	@Override
	public String getName() {
		return TraceObjectInterfaceUtils.getValue(object, getLoadedSnap(),
			TargetObject.DISPLAY_ATTRIBUTE_NAME, String.class, "");
	}

	@Override
	public void setRange(AddressRange range) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(getLifespan(), TargetModule.RANGE_ATTRIBUTE_NAME, range);
		}
	}

	@Override
	public AddressRange getRange() {
		return TraceObjectInterfaceUtils.getValue(object, getLoadedSnap(),
			TargetModule.RANGE_ATTRIBUTE_NAME, AddressRange.class, null);
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
	public void setLifespan(Range<Long> lifespan) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			TraceObjectInterfaceUtils.setLifespan(TraceObjectModule.class, object, lifespan);
			for (TraceObjectSection section : getSections()) {
				section.getObject().setLifespan(lifespan);
			}
		}
	}

	@Override
	public Range<Long> getLifespan() {
		return object.getLifespan();
	}

	@Override
	public void setLoadedSnap(long loadedSnap) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setLifespan(DBTraceUtils.toRange(loadedSnap, getUnloadedSnap()));
		}
	}

	@Override
	public long getLoadedSnap() {
		return object.getMinSnap();
	}

	@Override
	public void setUnloadedSnap(long unloadedSnap) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setLifespan(DBTraceUtils.toRange(getLoadedSnap(), unloadedSnap));
		}
	}

	@Override
	public long getUnloadedSnap() {
		return object.getMaxSnap();
	}

	@Override
	public Collection<? extends TraceObjectSection> getSections() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return object.querySuccessorsInterface(getLifespan(), TraceObjectSection.class)
					.collect(Collectors.toSet());
		}
	}

	@Override
	public TraceObjectSection getSectionByName(String sectionName) {
		PathMatcher matcher = object.getTargetSchema().searchFor(TargetSection.class, true);
		PathMatcher applied = matcher.applyKeys(List.of(sectionName));
		return object.getSuccessors(getLifespan(), applied)
				.map(p -> p.getLastChild(object).queryInterface(TraceObjectSection.class))
				.findAny()
				.orElse(null);
	}

	@Override
	public void delete() {
		object.deleteTree();
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
