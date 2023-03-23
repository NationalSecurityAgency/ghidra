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
package ghidra.app.plugin.core.debug.service.model.record;

import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;

import com.google.gson.Gson;
import com.google.gson.JsonElement;

import db.Transaction;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.TargetDataType;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetAttacher.TargetAttachKind;
import ghidra.dbg.target.TargetAttacher.TargetAttachKindSet;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.dbg.target.TargetSteppable.TargetStepKindSet;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.TraceUniqueObject;
import ghidra.trace.model.target.*;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import utilities.util.IDKeyed;

class ObjectRecorder {
	protected final ObjectBasedTraceRecorder recorder;
	protected final TraceObjectManager objectManager;
	protected final boolean isSupportsFocus;
	protected final boolean isSupportsActivation;

	private final BidiMap<IDKeyed<TargetObject>, IDKeyed<TraceObject>> objectMap =
		new DualHashBidiMap<>();

	protected ObjectRecorder(ObjectBasedTraceRecorder recorder) {
		this.recorder = recorder;
		this.objectManager = recorder.trace.getObjectManager();
		TargetObjectSchema schema = recorder.target.getSchema();
		this.isSupportsFocus = !schema.searchFor(TargetFocusScope.class, false).isEmpty();
		this.isSupportsActivation = !schema.searchFor(TargetActiveScope.class, false).isEmpty();

		try (Transaction tx = recorder.trace.openTransaction("Create root")) {
			objectManager.createRootObject(schema);
		}
	}

	protected TraceObject toTrace(TargetObject targetObject) {
		IDKeyed<TraceObject> traceObject = objectMap.get(new IDKeyed<>(targetObject));
		return traceObject == null ? null : traceObject.obj;
	}

	protected TargetObject toTarget(TraceObject traceObject) {
		IDKeyed<TargetObject> targetObject = objectMap.getKey(new IDKeyed<>(traceObject));
		return targetObject == null ? null : targetObject.obj;
	}

	/**
	 * List the names of interfaces on the object not already covered by the schema
	 * 
	 * @param object the object
	 * @return the comma-separated list of interface names
	 */
	protected String computeExtraInterfaces(TargetObject object) {
		Set<String> result = new LinkedHashSet<>(object.getInterfaceNames());
		for (Class<? extends TargetObject> iface : object.getSchema().getInterfaces()) {
			result.remove(DebuggerObjectModel.requireIfaceName(iface));
		}
		if (result.isEmpty()) {
			return null;
		}
		return result.stream().collect(Collectors.joining(","));
	}

	protected void recordCreated(long snap, TargetObject object) {
		TraceObject traceObject;
		if (object.isRoot()) {
			// Already have the root object
			traceObject = objectManager.getRootObject();
		}
		else {
			traceObject = objectManager.createObject(TraceObjectKeyPath.of(object.getPath()));
		}
		synchronized (objectMap) {
			IDKeyed<TraceObject> exists =
				objectMap.put(new IDKeyed<>(object), new IDKeyed<>(traceObject));
			if (exists != null) {
				Msg.error(this, "Received created for an object that already exists: " + exists);
			}
		}
		String extras = computeExtraInterfaces(object);
		// Note: null extras will erase previous value, if necessary.
		traceObject.setAttribute(Lifespan.nowOn(snap),
			TraceObject.EXTRA_INTERFACES_ATTRIBUTE_NAME, extras);
	}

	protected void recordInvalidated(long snap, TargetObject object) {
		if (object.isRoot()) {
			return;
		}
		IDKeyed<TraceObject> traceObject;
		synchronized (objectMap) {
			traceObject = objectMap.remove(new IDKeyed<>(object));
		}
		if (traceObject == null) {
			Msg.error(this, "Unknown object was invalidated: " + object);
			return;
		}
		traceObject.obj.removeTree(Lifespan.nowOn(snap));
	}

	protected String encodeEnum(Enum<?> e) {
		return e.name();
	}

	protected String encodeEnumSet(Set<? extends Enum<?>> s) {
		return s.stream()
				.sorted(Comparator.comparing(Enum::ordinal))
				.map(Enum::name)
				.collect(Collectors.joining(","));
	}

	protected Object mapAttribute(Object attribute) {
		if (attribute instanceof TargetObject) {
			TraceObject traceObject = toTrace((TargetObject) attribute);
			if (traceObject == null) {
				Msg.error(this, "Unknown object appeared as an attribute: " + attribute);
			}
			return traceObject;
		}
		if (attribute instanceof Address) {
			Address traceAddress = recorder.memoryMapper.targetToTrace((Address) attribute);
			if (traceAddress == null) {
				Msg.error(this, "Unmappable address appeared as an attribute: " + attribute);
			}
			return traceAddress;
		}
		if (attribute instanceof AddressRange) {
			AddressRange traceRange = recorder.memoryMapper.targetToTrace((AddressRange) attribute);
			if (traceRange == null) {
				Msg.error(this, "Unmappable range appeared as an attribute: " + attribute);
			}
			return traceRange;
		}
		if (attribute instanceof TargetAttachKind) {
			return encodeEnum((TargetAttachKind) attribute);
		}
		if (attribute instanceof TargetAttachKindSet) {
			return encodeEnumSet((TargetAttachKindSet) attribute);
		}
		if (attribute instanceof TargetBreakpointKind) {
			return encodeEnum((TargetBreakpointKind) attribute);
		}
		if (attribute instanceof TargetBreakpointKindSet) {
			return encodeEnumSet((TargetBreakpointKindSet) attribute);
		}
		if (attribute instanceof TargetDataType dataType) {
			// NOTE: some are also TargetObject, but that gets checked first
			JsonElement element = dataType.toJson();
			return new Gson().toJson(element);
		}
		if (attribute instanceof TargetExecutionState) {
			return encodeEnum((TargetExecutionState) attribute);
		}
		if (attribute instanceof TargetParameterMap) {
			return "[parameter map not recorded]";
		}
		if (attribute instanceof TargetStepKind) {
			return encodeEnum((TargetStepKind) attribute);
		}
		if (attribute instanceof TargetStepKindSet) {
			return encodeEnumSet((TargetStepKindSet) attribute);
		}
		return attribute;
	}

	protected void recordAttributes(long snap, TargetObject object, Collection<String> removed,
			Map<String, ?> added) {
		TraceObject traceObject;
		Map<String, Object> traceAdded = new HashMap<>();
		synchronized (objectMap) {
			traceObject = toTrace(object);
			if (traceObject == null) {
				Msg.error(this, "Unknown object had attributes changed: " + object);
				return;
			}
			for (Map.Entry<String, ?> entry : added.entrySet()) {
				Object value = mapAttribute(entry.getValue());
				if (value == null) {
					continue;
				}
				traceAdded.put(entry.getKey(), value);
			}
		}
		for (Map.Entry<String, Object> entry : traceAdded.entrySet()) {
			traceObject.setAttribute(Lifespan.nowOn(snap), entry.getKey(), entry.getValue());
		}
	}

	protected TraceObject mapElement(TargetObject element) {
		TraceObject traceObject = toTrace(element);
		if (traceObject == null) {
			Msg.error(this, "Unknown object appeared as an element: " + element);
			return null;
		}
		return traceObject;
	}

	protected void recordElements(long snap, TargetObject object, Collection<String> removed,
			Map<String, ? extends TargetObject> added) {
		TraceObject traceObject;
		Map<String, Object> traceAdded = new HashMap<>();
		synchronized (objectMap) {
			traceObject = toTrace(object);
			if (traceObject == null) {
				Msg.error(this, "Unknown object had attributes changed: " + object);
				return;
			}
			for (Map.Entry<String, ? extends TargetObject> entry : added.entrySet()) {
				Object value = mapElement(entry.getValue());
				if (value == null) {
					continue;
				}
				traceAdded.put(entry.getKey(), value);
			}
		}
		for (Map.Entry<String, Object> entry : traceAdded.entrySet()) {
			traceObject.setElement(Lifespan.nowOn(snap), entry.getKey(), entry.getValue());
		}
	}

	protected <T extends TargetObject, I extends TraceObjectInterface> T getTargetInterface(
			TraceUniqueObject traceUnique, Class<I> traceObjectIf, Class<T> targetObjectIf) {
		if (!traceObjectIf.isAssignableFrom(traceUnique.getClass())) {
			return null;
		}
		TraceObject traceObject = traceObjectIf.cast(traceUnique).getObject();
		return getTargetInterface(traceObject, targetObjectIf);
	}

	protected <T extends TargetObject> T getTargetInterface(TraceObject traceObject,
			Class<T> targetObjectIf) {
		TargetObject targetObject = toTarget(traceObject);
		return targetObject == null ? null : targetObject.as(targetObjectIf);
	}

	protected <I extends TraceObjectInterface> I getTraceInterface(TargetObject targetObject,
			Class<I> traceObjectIf) {
		TraceObject traceObject = toTrace(targetObject);
		return traceObject == null ? null : traceObject.queryInterface(traceObjectIf);
	}

	protected <T extends TargetObject> T getTargetFrameInterface(TraceThread thread, int frameLevel,
			Class<T> targetObjectIf) {
		if (thread == null) {
			return null;
		}
		TraceObject object = ((TraceObjectThread) thread).getObject();
		PathMatcher matcher = object.getTargetSchema().searchFor(targetObjectIf, false);
		PathPattern pattern = matcher.getSingletonPattern();
		if (pattern == null) {
			return null;
		}
		PathPredicates applied;
		if (pattern.countWildcards() == 0) {
			if (frameLevel != 0) {
				return null;
			}
			applied = pattern;
		}
		else if (pattern.countWildcards() == 1) {
			applied = pattern.applyIntKeys(frameLevel);
		}
		else {
			return null;
		}
		TraceObjectValPath found = object
				.getSuccessors(Lifespan.at(recorder.getSnap()), applied)
				.findAny()
				.orElse(null);
		if (found == null) {
			return null;
		}
		TraceObject last = found.getDestination(null);
		if (last == null) {
			return null;
		}
		return getTargetInterface(last, targetObjectIf);
	}

	protected <T extends TargetObject> List<T> collectTargetSuccessors(TargetObject targetSeed,
			Class<T> targetIf, boolean requireCanonical) {
		// TODO: Should this really go through the database?
		TraceObject seed = toTrace(targetSeed);
		if (seed == null) {
			return List.of();
		}
		return seed.querySuccessorsTargetInterface(Lifespan.at(recorder.getSnap()), targetIf,
			requireCanonical)
				.map(p -> toTarget(p.getDestination(seed)).as(targetIf))
				.collect(Collectors.toList());
	}
}
