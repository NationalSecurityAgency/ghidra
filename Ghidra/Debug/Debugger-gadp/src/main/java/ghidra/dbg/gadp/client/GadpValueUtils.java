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
package ghidra.dbg.gadp.client;

import static ghidra.lifecycle.Unfinished.TODO;

import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import com.google.protobuf.ByteString;

import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.*;
import ghidra.dbg.attributes.TargetObjectList.DefaultTargetObjectList;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.gadp.protocol.Gadp.ModelObjectDelta;
import ghidra.dbg.target.TargetAttacher.TargetAttachKind;
import ghidra.dbg.target.TargetAttacher.TargetAttachKindSet;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.dbg.target.TargetSteppable.TargetStepKindSet;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;
import ghidra.util.Msg;

public enum GadpValueUtils {
	;

	public static TargetObjectList<?> getObjList(DebuggerObjectModel model, Gadp.PathList list) {
		TargetObjectList<TargetObject> result = new DefaultTargetObjectList<>();
		for (Gadp.Path path : list.getPathList()) {
			result.add(model.getModelObject(path.getEList()));
		}
		return result;
	}

	public static TargetBreakpointKindSet getBreakKindSet(Gadp.BreakKindsSet set) {
		return TargetBreakpointKindSet.copyOf(
			set.getKList().stream().map(k -> getBreakKind(k)).collect(Collectors.toSet()));
	}

	public static TargetBreakpointKind getBreakKind(Gadp.BreakKind kind) {
		switch (kind) {
			case BK_READ:
				return TargetBreakpointKind.READ;
			case BK_WRITE:
				return TargetBreakpointKind.WRITE;
			case BK_EXECUTE:
				return TargetBreakpointKind.HW_EXECUTE;
			case BK_SOFTWARE:
				return TargetBreakpointKind.SW_EXECUTE;
			default:
				throw new IllegalArgumentException();
		}
	}

	public static Gadp.BreakKindsSet makeBreakKindSet(Set<TargetBreakpointKind> set) {
		return Gadp.BreakKindsSet.newBuilder()
				.addAllK(set.stream().map(k -> makeBreakKind(k)).collect(Collectors.toList()))
				.build();
	}

	public static Gadp.BreakKind makeBreakKind(TargetBreakpointKind kind) {
		switch (kind) {
			case READ:
				return Gadp.BreakKind.BK_READ;
			case WRITE:
				return Gadp.BreakKind.BK_WRITE;
			case HW_EXECUTE:
				return Gadp.BreakKind.BK_EXECUTE;
			case SW_EXECUTE:
				return Gadp.BreakKind.BK_SOFTWARE;
			default:
				throw new IllegalArgumentException();
		}
	}

	public static TargetAttachKindSet getAttachKindSet(Gadp.AttachKindSet set) {
		return TargetAttachKindSet.copyOf(
			set.getKList().stream().map(k -> getAttachKind(k)).collect(Collectors.toSet()));
	}

	public static TargetAttachKind getAttachKind(Gadp.AttachKind kind) {
		switch (kind) {
			case AK_BY_OBJECT_REF:
				return TargetAttachKind.BY_OBJECT_REF;
			case AK_BY_ID:
				return TargetAttachKind.BY_ID;
			default:
				throw new IllegalArgumentException();
		}
	}

	public static Gadp.AttachKindSet makeAttachKindSet(Set<TargetAttachKind> set) {
		return Gadp.AttachKindSet.newBuilder()
				.addAllK(set.stream().map(k -> makeAttachKind(k)).collect(Collectors.toList()))
				.build();
	}

	public static Gadp.AttachKind makeAttachKind(TargetAttachKind kind) {
		switch (kind) {
			case BY_OBJECT_REF:
				return Gadp.AttachKind.AK_BY_OBJECT_REF;
			case BY_ID:
				return Gadp.AttachKind.AK_BY_ID;
			default:
				throw new IllegalArgumentException();
		}
	}

	public static TargetStepKindSet getStepKindSet(Gadp.StepKindsSet set) {
		return TargetStepKindSet.copyOf(
			set.getKList().stream().map(k -> getStepKind(k)).collect(Collectors.toSet()));
	}

	public static TargetStepKind getStepKind(Gadp.StepKind kind) {
		switch (kind) {
			case SK_ADVANCE:
				return TargetStepKind.ADVANCE;
			case SK_FINISH:
				return TargetStepKind.FINISH;
			case SK_INTO:
				return TargetStepKind.INTO;
			case SK_LINE:
				return TargetStepKind.LINE;
			case SK_OVER:
				return TargetStepKind.OVER;
			case SK_OVER_LINE:
				return TargetStepKind.OVER_LINE;
			case SK_RETURN:
				return TargetStepKind.RETURN;
			case SK_SKIP:
				return TargetStepKind.SKIP;
			case SK_UNTIL:
				return TargetStepKind.UNTIL;
			case SK_EXTENDED:
				return TargetStepKind.EXTENDED;
			default:
				throw new IllegalArgumentException();
		}
	}

	public static Gadp.StepKind makeStepKind(TargetStepKind kind) {
		switch (kind) {
			case ADVANCE:
				return Gadp.StepKind.SK_ADVANCE;
			case FINISH:
				return Gadp.StepKind.SK_FINISH;
			case INTO:
				return Gadp.StepKind.SK_INTO;
			case LINE:
				return Gadp.StepKind.SK_LINE;
			case OVER:
				return Gadp.StepKind.SK_OVER;
			case OVER_LINE:
				return Gadp.StepKind.SK_OVER_LINE;
			case RETURN:
				return Gadp.StepKind.SK_RETURN;
			case SKIP:
				return Gadp.StepKind.SK_SKIP;
			case UNTIL:
				return Gadp.StepKind.SK_UNTIL;
			case EXTENDED:
				return Gadp.StepKind.SK_EXTENDED;
			default:
				throw new IllegalArgumentException();
		}
	}

	public static TargetExecutionState getExecutionState(Gadp.ExecutionState state) {
		switch (state) {
			case ES_INACTIVE:
				return TargetExecutionState.INACTIVE;
			case ES_ALIVE:
				return TargetExecutionState.ALIVE;
			case ES_STOPPED:
				return TargetExecutionState.STOPPED;
			case ES_RUNNING:
				return TargetExecutionState.RUNNING;
			case ES_TERMINATED:
				return TargetExecutionState.TERMINATED;
			default:
				throw new IllegalArgumentException();
		}
	}

	public static Gadp.ExecutionState makeExecutionState(TargetExecutionState state) {
		switch (state) {
			case INACTIVE:
				return Gadp.ExecutionState.ES_INACTIVE;
			case ALIVE:
				return Gadp.ExecutionState.ES_ALIVE;
			case STOPPED:
				return Gadp.ExecutionState.ES_STOPPED;
			case RUNNING:
				return Gadp.ExecutionState.ES_RUNNING;
			case TERMINATED:
				return Gadp.ExecutionState.ES_TERMINATED;
			default:
				throw new IllegalArgumentException();
		}
	}

	public static TargetEventType getTargetEventType(Gadp.TargetEventType type) {
		switch (type) {
			default:
			case EV_STOPPED:
				return TargetEventType.STOPPED;
			case EV_RUNNING:
				return TargetEventType.RUNNING;
			case EV_PROCESS_CREATED:
				return TargetEventType.PROCESS_CREATED;
			case EV_PROCESS_EXITED:
				return TargetEventType.PROCESS_EXITED;
			case EV_THREAD_CREATED:
				return TargetEventType.THREAD_CREATED;
			case EV_THREAD_EXITED:
				return TargetEventType.THREAD_EXITED;
			case EV_MODULE_LOADED:
				return TargetEventType.MODULE_LOADED;
			case EV_MODULE_UNLOADED:
				return TargetEventType.MODULE_UNLOADED;
			case EV_BREAKPOINT_HIT:
				return TargetEventType.BREAKPOINT_HIT;
			case EV_STEP_COMPLETED:
				return TargetEventType.STEP_COMPLETED;
			case EV_EXCEPTION:
				return TargetEventType.EXCEPTION;
			case EV_SIGNAL:
				return TargetEventType.SIGNAL;
		}
	}

	public static Gadp.TargetEventType makeTargetEventType(TargetEventType type) {
		switch (type) {
			default:
			case STOPPED:
				return Gadp.TargetEventType.EV_STOPPED;
			case RUNNING:
				return Gadp.TargetEventType.EV_RUNNING;
			case PROCESS_CREATED:
				return Gadp.TargetEventType.EV_PROCESS_CREATED;
			case PROCESS_EXITED:
				return Gadp.TargetEventType.EV_PROCESS_EXITED;
			case THREAD_CREATED:
				return Gadp.TargetEventType.EV_THREAD_CREATED;
			case THREAD_EXITED:
				return Gadp.TargetEventType.EV_THREAD_EXITED;
			case MODULE_LOADED:
				return Gadp.TargetEventType.EV_MODULE_LOADED;
			case MODULE_UNLOADED:
				return Gadp.TargetEventType.EV_MODULE_UNLOADED;
			case BREAKPOINT_HIT:
				return Gadp.TargetEventType.EV_BREAKPOINT_HIT;
			case STEP_COMPLETED:
				return Gadp.TargetEventType.EV_STEP_COMPLETED;
			case EXCEPTION:
				return Gadp.TargetEventType.EV_EXCEPTION;
			case SIGNAL:
				return Gadp.TargetEventType.EV_SIGNAL;
		}
	}

	/**
	 * TODO: Document me
	 * 
	 * @see GadpClient#getAddress(ghidra.dbg.gadp.protocol.Gadp.Address)
	 * @param address
	 * @return
	 */
	public static Gadp.Address makeAddress(Address address) {
		return Gadp.Address.newBuilder()
				.setSpace(address.getAddressSpace().getName())
				.setOffset(address.getOffset())
				.build();
	}

	public static Gadp.AddressRange makeRange(AddressRange range) {
		return Gadp.AddressRange.newBuilder()
				.setSpace(range.getAddressSpace().getName())
				.setOffset(range.getMinAddress().getOffset())
				.setExtend((int) (range.getLength() - 1))
				.build();
	}

	public static Gadp.ModelObjectDelta makeElementDelta(List<String> parentPath,
			Delta<?, ?> delta) {
		ModelObjectDelta.Builder builder = Gadp.ModelObjectDelta.newBuilder()
				.addAllRemoved(delta.getKeysRemoved());
		for (Entry<String, ?> ent : delta.added.entrySet()) {
			builder.addAdded(makeIndexedValue(parentPath, ent));
		}
		return builder.build();
	}

	public static Gadp.ModelObjectDelta makeAttributeDelta(List<String> parentPath,
			Delta<?, ?> delta) {
		ModelObjectDelta.Builder builder = Gadp.ModelObjectDelta.newBuilder()
				.addAllRemoved(delta.getKeysRemoved());
		for (Entry<String, ?> ent : delta.added.entrySet()) {
			builder.addAdded(makeNamedValue(parentPath, ent));
		}
		return builder.build();
	}

	public static Gadp.Path makePath(List<String> path) {
		return Gadp.Path.newBuilder().addAllE(path).build();
	}

	public static Gadp.Path makePath(TargetObject obj) {
		return makePath(obj.getPath());
	}

	public static Gadp.PathList makePathList(TargetObjectList<?> list) {
		return Gadp.PathList.newBuilder()
				.addAllPath(list.stream().map(p -> makePath(p)).collect(Collectors.toList()))
				.build();
	}

	public static Gadp.RegisterValue makeRegisterValue(Map.Entry<String, byte[]> e) {
		return Gadp.RegisterValue.newBuilder()
				.setName(e.getKey())
				.setContent(ByteString.copyFrom(e.getValue()))
				.build();
	}

	public static Collection<Gadp.RegisterValue> makeRegisterValues(Map<String, byte[]> map) {
		return map.entrySet()
				.stream()
				.map(GadpValueUtils::makeRegisterValue)
				.collect(Collectors.toList());
	}

	public static Map<String, byte[]> getRegisterValueMap(Collection<Gadp.RegisterValue> values) {
		return values.stream()
				.collect(Collectors.toMap(v -> v.getName(), v -> v.getContent().toByteArray()));
	}

	public static Gadp.StepKindsSet makeStepKindSet(Set<TargetStepKind> set) {
		return Gadp.StepKindsSet.newBuilder()
				.addAllK(set.stream().map(k -> makeStepKind(k)).collect(Collectors.toList()))
				.build();
	}

	// TODO: Remove type-specific collections, and just use collections of values (objects)
	// NOTE: Map should probably be strictly strings for keys.
	public static Gadp.StringList makeStringList(Collection<String> col) {
		return Gadp.StringList.newBuilder().addAllS(col).build();
	}

	public static TargetStringList getStringList(Gadp.StringList list) {
		return TargetStringList.copyOf(list.getSList());
	}

	public static Class<?> getValueType(Gadp.ValueType type) {
		switch (type) {
			case VT_VOID:
				return Void.class;
			case VT_BOOL:
				return Boolean.class;
			case VT_INT:
				return Integer.class;
			case VT_LONG:
				return Long.class;
			case VT_FLOAT:
				return Float.class;
			case VT_DOUBLE:
				return Double.class;
			case VT_BYTES:
				return byte[].class;
			case VT_STRING:
				return String.class;
			case VT_STRING_LIST:
				return TargetStringList.class;
			case VT_ADDRESS:
				return Address.class;
			case VT_RANGE:
				return AddressRange.class;
			case VT_BREAK_KIND_SET:
				return TargetBreakpointKindSet.class;
			case VT_EXECUTION_STATE:
				return TargetExecutionState.class;
			case VT_STEP_KIND_SET:
				return TargetStepKindSet.class;
			case VT_PRIMITIVE_KIND:
				return TargetPrimitiveDataType.class;
			case VT_DATA_TYPE:
				return TargetDataType.class;
			case VT_PATH:
				return TargetObject.class;
			case VT_PATH_LIST:
				return TargetObjectList.class;
			case VT_TYPE:
				return Class.class;
			case UNRECOGNIZED:
			default:
				throw new AssertionError("Unrecgonized type: " + type);
		}
	}

	private static <T> ParameterDescription<T> getParameterDescription(Class<T> valueType,
			DebuggerObjectModel model, Gadp.Parameter param) {
		if (param.getChoicesCount() != 0) {
			return ParameterDescription.choices(valueType, param.getName(),
				getValues(model, param.getChoicesList()).stream()
						.map(valueType::cast)
						.collect(Collectors.toList()),
				param.getDisplay(), param.getDescription());
		}
		return ParameterDescription.create(valueType, param.getName(), param.getRequired(),
			valueType.cast(getValue(model, null, param.getDefaultValue())), param.getDisplay(),
			param.getDescription());
	}

	public static ParameterDescription<?> getParameterDescription(DebuggerObjectModel model,
			Gadp.Parameter param) {
		return getParameterDescription(getValueType(param.getType()), model, param);

	}

	public static Map<String, ParameterDescription<?>> getParameters(DebuggerObjectModel model,
			Gadp.ParameterList params) {
		return TargetMethod.makeParameters(
			params.getParameterList().stream().map(p -> getParameterDescription(model, p)));
	}

	public static Gadp.ValueType makeValueType(Class<?> type) {
		if (type == Void.class) {
			return Gadp.ValueType.VT_VOID;
		}
		if (type == Boolean.class) {
			return Gadp.ValueType.VT_BOOL;
		}
		if (type == Integer.class) {
			return Gadp.ValueType.VT_INT;
		}
		if (type == Long.class) {
			return Gadp.ValueType.VT_LONG;
		}
		if (type == Float.class) {
			return Gadp.ValueType.VT_FLOAT;
		}
		if (type == Double.class) {
			return Gadp.ValueType.VT_DOUBLE;
		}
		if (type == byte[].class) {
			return Gadp.ValueType.VT_BYTES;
		}
		if (type == String.class) {
			return Gadp.ValueType.VT_STRING;
		}
		if (type == TargetStringList.class) {
			return Gadp.ValueType.VT_STRING_LIST;
		}
		if (type == Address.class) {
			return Gadp.ValueType.VT_ADDRESS;
		}
		if (type == AddressRange.class) {
			return Gadp.ValueType.VT_RANGE;
		}
		if (type == TargetBreakpointKindSet.class) {
			return Gadp.ValueType.VT_BREAK_KIND_SET;
		}
		if (type == TargetExecutionState.class) {
			return Gadp.ValueType.VT_EXECUTION_STATE;
		}
		if (type == TargetStepKindSet.class) {
			return Gadp.ValueType.VT_STEP_KIND_SET;
		}
		if (type == TargetPrimitiveDataType.class) {
			return Gadp.ValueType.VT_PRIMITIVE_KIND;
		}
		if (type == TargetDataType.class) {
			return Gadp.ValueType.VT_DATA_TYPE;
		}
		if (type == TargetObject.class) {
			return Gadp.ValueType.VT_PATH;
		}
		if (type == TargetObjectList.class) {
			return Gadp.ValueType.VT_PATH_LIST;
		}
		if (type == Class.class) {
			return Gadp.ValueType.VT_TYPE;
		}
		throw new IllegalArgumentException("Cannot encode type: " + type);
	}

	public static Gadp.Parameter makeParameter(ParameterDescription<?> desc) {
		return Gadp.Parameter.newBuilder()
				.setType(makeValueType(desc.type))
				.setName(desc.name)
				.setDefaultValue(makeValue(null, desc.defaultValue))
				.setRequired(desc.required)
				.setDisplay(desc.display)
				.setDescription(desc.description)
				.addAllChoices(makeValues(desc.choices))
				.build();
	}

	public static Gadp.ParameterList makeParameterList(TargetParameterMap map) {
		return Gadp.ParameterList.newBuilder()
				.addAllParameter(
					map.values().stream().map(d -> makeParameter(d)).collect(Collectors.toList()))
				.build();
	}

	public static TargetObject getTargetObjectNonLink(List<String> path, Object value) {
		if (!(value instanceof TargetObject)) {
			return null;
		}
		TargetObject obj = (TargetObject) value;
		if (!Objects.equals(obj.getPath(), path)) {
			return null;
		}
		return obj;
	}

	public static Gadp.Value makeValue(List<String> path, Object value) {
		Gadp.Value.Builder b = Gadp.Value.newBuilder();
		if (value instanceof Boolean) {
			b.setBoolValue((Boolean) value);
		}
		else if (value instanceof Integer) {
			b.setIntValue((Integer) value);
		}
		else if (value instanceof Long) {
			b.setLongValue((Long) value);
		}
		else if (value instanceof Float) {
			b.setFloatValue((Float) value);
		}
		else if (value instanceof Double) {
			b.setDoubleValue((Double) value);
		}
		else if (value instanceof byte[]) {
			b.setBytesValue(ByteString.copyFrom((byte[]) value));
		}
		else if (value instanceof String) {
			b.setStringValue((String) value);
		}
		else if (value instanceof TargetStringList) {
			b.setStringListValue(makeStringList((TargetStringList) value));
		}
		else if (value instanceof Address) {
			b.setAddressValue(makeAddress((Address) value));
		}
		else if (value instanceof AddressRange) {
			b.setRangeValue(makeRange((AddressRange) value));
		}
		else if (value instanceof TargetAttachKindSet) {
			b.setAttachKindsValue(makeAttachKindSet((TargetAttachKindSet) value));
		}
		else if (value instanceof TargetBreakpointKindSet) {
			b.setBreakKindsValue(makeBreakKindSet((TargetBreakpointKindSet) value));
		}
		else if (value instanceof TargetExecutionState) {
			b.setExecStateValue(makeExecutionState((TargetExecutionState) value));
		}
		else if (value instanceof TargetStepKindSet) {
			b.setStepKindsValue(makeStepKindSet((TargetStepKindSet) value));
		}
		// TODO: TargetPrimitiveDataType?
		// TODO: TargetDataType?
		else if (value instanceof TargetParameterMap) {
			b.setParametersValue(makeParameterList((TargetParameterMap) value));
		}
		else if (path != null && getTargetObjectNonLink(path, value) != null) {
			// This case MUST precede TargetObjectRef
			b.setObjectStub(Gadp.ModelObjectStub.getDefaultInstance());
			// NOTE: Never produce info. That is a special case for object retrieval.
		}
		else if (value instanceof TargetObject) {
			b.setPathValue(makePath((TargetObject) value));
		}
		else if (value instanceof TargetObjectList) {
			b.setPathListValue(makePathList((TargetObjectList<?>) value));
		}
		else if (value instanceof Class) {
			b.setTypeValue(makeValueType((Class<?>) value));
		}
		else {
			throw new IllegalArgumentException(
				"Cannot encode value: " + value + " (of type " + value.getClass() + ")");
		}
		return b.build();
	}

	public static Gadp.NamedValue makeNamedValue(Map.Entry<String, ?> ent) {
		return makeNamedValue(null, ent);
	}

	public static Gadp.NamedValue makeNamedValue(List<String> parentPath,
			Map.Entry<String, ?> ent) {
		List<String> path = parentPath == null ? null : PathUtils.extend(parentPath, ent.getKey());
		return Gadp.NamedValue.newBuilder()
				.setName(ent.getKey())
				.setValue(makeValue(path, ent.getValue()))
				.build();
	}

	public static Gadp.NamedValue makeIndexedValue(List<String> parentPath,
			Map.Entry<String, ?> ent) {
		List<String> path = parentPath == null ? null : PathUtils.index(parentPath, ent.getKey());
		return Gadp.NamedValue.newBuilder()
				.setName(ent.getKey())
				.setValue(makeValue(path, ent.getValue()))
				.build();
	}

	public static Address getAddress(DebuggerObjectModel model, Gadp.Address addr) {
		return model.getAddress(addr.getSpace(), addr.getOffset());
	}

	public static AddressRange getAddressRange(DebuggerObjectModel model, Gadp.AddressRange range) {
		Address min = model.getAddress(range.getSpace(), range.getOffset());
		return new AddressRangeImpl(min, min.add(Integer.toUnsignedLong(range.getExtend())));
	}

	public static Object getValue(DebuggerObjectModel model, List<String> path, Gadp.Value value) {
		switch (value.getSpecCase()) {
			case BOOL_VALUE:
				return value.getBoolValue();
			case INT_VALUE:
				return value.getIntValue();
			case LONG_VALUE:
				return value.getLongValue();
			case FLOAT_VALUE:
				return value.getFloatValue();
			case DOUBLE_VALUE:
				return value.getDoubleValue();
			case BYTES_VALUE:
				return value.getBytesValue().toByteArray();
			case STRING_VALUE:
				return value.getStringValue();
			case STRING_LIST_VALUE:
				return getStringList(value.getStringListValue());
			case ADDRESS_VALUE:
				return getAddress(model, value.getAddressValue());
			case RANGE_VALUE:
				return getAddressRange(model, value.getRangeValue());
			case ATTACH_KINDS_VALUE:
				return getAttachKindSet(value.getAttachKindsValue());
			case BREAK_KINDS_VALUE:
				return getBreakKindSet(value.getBreakKindsValue());
			case EXEC_STATE_VALUE:
				return getExecutionState(value.getExecStateValue());
			case STEP_KINDS_VALUE:
				return getStepKindSet(value.getStepKindsValue());
			case PRIMITIVE_KIND_VALUE:
				return TODO("Marhsalling types over GADP", value.getPrimitiveKindValue());
			case DATA_TYPE_VALUE:
				return TODO("Marshalling types over GADP", value.getDataTypeValue());
			case PARAMETERS_VALUE:
				return getParameters(model, value.getParametersValue());
			case PATH_VALUE:
				return model.getModelObject(value.getPathValue().getEList());
			case PATH_LIST_VALUE:
				return getObjList(model, value.getPathListValue());
			case OBJECT_STUB:
				return model.getModelObject(path);
			case TYPE_VALUE:
				return getValueType(value.getTypeValue());
			case SPEC_NOT_SET:
				return null;
			default:
				Msg.error(GadpValueUtils.class, "Got unknown value type: " + value);
				return null;
		}
	}

	public static Object getAttributeValue(TargetObject object, Gadp.NamedValue attr) {
		return getValue(object.getModel(), PathUtils.extend(object.getPath(), attr.getName()),
			attr.getValue());
	}

	public static GadpClientTargetObject getElementValue(TargetObject object,
			Gadp.NamedValue elem) {
		Object value = getValue(object.getModel(),
			PathUtils.index(object.getPath(), elem.getName()), elem.getValue());
		if (!(value instanceof GadpClientTargetObject)) {
			Msg.error(GadpValueUtils.class, "Received non-object-valued element: " + elem);
			return null;
		}
		return (GadpClientTargetObject) value;
	}

	public static Map<String, Object> getAttributeMap(GadpClientTargetObject object,
			List<Gadp.NamedValue> list) {
		Map<String, Object> result = new LinkedHashMap<>();
		for (Gadp.NamedValue attr : list) {
			Object val = GadpValueUtils.getAttributeValue(object, attr);
			if (result.put(attr.getName(), val) != null) {
				Msg.warn(GadpValueUtils.class, "Received duplicate attribute: " + attr);
			}
		}
		return result;
	}

	public static List<Object> getValues(DebuggerObjectModel model, List<Gadp.Value> values) {
		// Use null for path, since the list cannot refer to itself as an object
		return values.stream().map(v -> getValue(model, null, v)).collect(Collectors.toList());
	}

	public static List<Gadp.Value> makeValues(Collection<?> values) {
		return values.stream().map(v -> makeValue(null, v)).collect(Collectors.toList());
	}

	public static List<Gadp.NamedValue> makeArguments(Map<String, ?> arguments) {
		return arguments.entrySet()
				.stream()
				.map(ent -> makeNamedValue(ent))
				.collect(Collectors.toList());
	}

	public static Map<String, GadpClientTargetObject> getElementMap(GadpClientTargetObject parent,
			List<Gadp.NamedValue> list) {
		Map<String, GadpClientTargetObject> result = new LinkedHashMap<>();
		for (Gadp.NamedValue elem : list) {
			GadpClientTargetObject val = GadpValueUtils.getElementValue(parent, elem);
			if (val == null) {
				continue;
			}
			if (result.put(elem.getName(), val) != null) {
				Msg.warn(GadpValueUtils.class, "Received duplicate element: " + elem);
			}
		}
		return result;
	}

	public static Map<String, ?> getArguments(DebuggerObjectModel model,
			List<Gadp.NamedValue> arguments) {
		return arguments.stream()
				.collect(
					Collectors.toMap(a -> a.getName(), a -> getValue(model, null, a.getValue())));
	}
}
