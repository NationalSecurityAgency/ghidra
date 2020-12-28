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
package ghidra.dbg.gadp.util;

import static ghidra.lifecycle.Unfinished.TODO;

import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import com.google.protobuf.ByteString;

import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.*;
import ghidra.dbg.attributes.TargetObjectRefList.DefaultTargetObjectRefList;
import ghidra.dbg.gadp.GadpRegistry;
import ghidra.dbg.gadp.client.GadpClient;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.gadp.protocol.Gadp.ModelObjectDelta;
import ghidra.dbg.gadp.protocol.Gadp.ModelObjectInfo;
import ghidra.dbg.target.TargetAttacher.TargetAttachKind;
import ghidra.dbg.target.TargetAttacher.TargetAttachKindSet;
import ghidra.dbg.target.TargetBreakpointContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetObject.TargetUpdateMode;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.dbg.target.TargetSteppable.TargetStepKindSet;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;
import ghidra.util.Msg;

public enum GadpValueUtils {
	;

	public static TargetObjectRefList<?> getRefList(DebuggerObjectModel model, Gadp.PathList list) {
		TargetObjectRefList<TargetObjectRef> result = new DefaultTargetObjectRefList<>();
		for (Gadp.Path path : list.getPathList()) {
			result.add(model.createRef(path.getEList()));
		}
		return result;
	}

	public static TargetBreakpointKindSet getBreakKindSet(Gadp.BreakKindsSet set) {
		return TargetBreakpointKindSet.copyOf(
			set.getKList().stream().map(k -> getBreakKind(k)).collect(Collectors.toSet()));
	}

	public static TargetBreakpointKind getBreakKind(Gadp.BreakKind kind) {
		switch (kind) {
			case READ:
				return TargetBreakpointKind.READ;
			case WRITE:
				return TargetBreakpointKind.WRITE;
			case EXECUTE:
				return TargetBreakpointKind.EXECUTE;
			case SOFTWARE:
				return TargetBreakpointKind.SOFTWARE;
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
				return Gadp.BreakKind.READ;
			case WRITE:
				return Gadp.BreakKind.WRITE;
			case EXECUTE:
				return Gadp.BreakKind.EXECUTE;
			case SOFTWARE:
				return Gadp.BreakKind.SOFTWARE;
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
			case BY_OBJECT_REF:
				return TargetAttachKind.BY_OBJECT_REF;
			case BY_ID:
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
				return Gadp.AttachKind.BY_OBJECT_REF;
			case BY_ID:
				return Gadp.AttachKind.BY_ID;
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
			case ADVANCE:
				return TargetStepKind.ADVANCE;
			case FINISH:
				return TargetStepKind.FINISH;
			case INTO:
				return TargetStepKind.INTO;
			case LINE:
				return TargetStepKind.LINE;
			case OVER:
				return TargetStepKind.OVER;
			case OVER_LINE:
				return TargetStepKind.OVER_LINE;
			case RETURN:
				return TargetStepKind.RETURN;
			case SKIP:
				return TargetStepKind.SKIP;
			case UNTIL:
				return TargetStepKind.UNTIL;
			default:
				throw new IllegalArgumentException();
		}
	}

	public static Gadp.StepKind makeStepKind(TargetStepKind kind) {
		switch (kind) {
			case ADVANCE:
				return Gadp.StepKind.ADVANCE;
			case FINISH:
				return Gadp.StepKind.FINISH;
			case INTO:
				return Gadp.StepKind.INTO;
			case LINE:
				return Gadp.StepKind.LINE;
			case OVER:
				return Gadp.StepKind.OVER;
			case OVER_LINE:
				return Gadp.StepKind.OVER_LINE;
			case RETURN:
				return Gadp.StepKind.RETURN;
			case SKIP:
				return Gadp.StepKind.SKIP;
			case UNTIL:
				return Gadp.StepKind.UNTIL;
			default:
				throw new IllegalArgumentException();
		}
	}

	public static TargetExecutionState getExecutionState(Gadp.ExecutionState state) {
		switch (state) {
			case INACTIVE:
				return TargetExecutionState.INACTIVE;
			case ALIVE:
				return TargetExecutionState.ALIVE;
			case STOPPED:
				return TargetExecutionState.STOPPED;
			case RUNNING:
				return TargetExecutionState.RUNNING;
			case TERMINATED:
				return TargetExecutionState.TERMINATED;
			default:
				throw new IllegalArgumentException();
		}
	}

	public static Gadp.ExecutionState makeExecutionState(TargetExecutionState state) {
		switch (state) {
			case INACTIVE:
				return Gadp.ExecutionState.INACTIVE;
			case ALIVE:
				return Gadp.ExecutionState.ALIVE;
			case STOPPED:
				return Gadp.ExecutionState.STOPPED;
			case RUNNING:
				return Gadp.ExecutionState.RUNNING;
			case TERMINATED:
				return Gadp.ExecutionState.TERMINATED;
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
			case PROCESS_CREATED:
				return TargetEventType.PROCESS_CREATED;
			case PROCESS_EXITED:
				return TargetEventType.PROCESS_EXITED;
			case THREAD_CREATED:
				return TargetEventType.THREAD_CREATED;
			case THREAD_EXITED:
				return TargetEventType.THREAD_EXITED;
			case MODULE_LOADED:
				return TargetEventType.MODULE_LOADED;
			case MODULE_UNLOADED:
				return TargetEventType.MODULE_UNLOADED;
			case BREAKPOINT_HIT:
				return TargetEventType.BREAKPOINT_HIT;
			case STEP_COMPLETED:
				return TargetEventType.STEP_COMPLETED;
			case EXCEPTION:
				return TargetEventType.EXCEPTION;
			case SIGNAL:
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
				return Gadp.TargetEventType.PROCESS_CREATED;
			case PROCESS_EXITED:
				return Gadp.TargetEventType.PROCESS_EXITED;
			case THREAD_CREATED:
				return Gadp.TargetEventType.THREAD_CREATED;
			case THREAD_EXITED:
				return Gadp.TargetEventType.THREAD_EXITED;
			case MODULE_LOADED:
				return Gadp.TargetEventType.MODULE_LOADED;
			case MODULE_UNLOADED:
				return Gadp.TargetEventType.MODULE_UNLOADED;
			case BREAKPOINT_HIT:
				return Gadp.TargetEventType.BREAKPOINT_HIT;
			case STEP_COMPLETED:
				return Gadp.TargetEventType.STEP_COMPLETED;
			case EXCEPTION:
				return Gadp.TargetEventType.EXCEPTION;
			case SIGNAL:
				return Gadp.TargetEventType.SIGNAL;
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

	public static Gadp.ModelObjectInfo makeInfo(TargetObject obj) {
		ModelObjectInfo.Builder builder = Gadp.ModelObjectInfo.newBuilder()
				.setPath(GadpValueUtils.makePath(obj.getPath()))
				.setTypeHint(obj.getTypeHint())
				.addAllInterface(GadpRegistry.getInterfaceNames(obj));

		builder.addAllElementIndex(obj.getCachedElements().keySet());
		for (Entry<String, ?> ent : obj.getCachedAttributes().entrySet()) {
			builder.addAttribute(makeAttribute(obj, ent));
		}

		return builder.build();
	}

	public static Gadp.ModelObjectDelta makeDelta(TargetObject parent,
			Delta<?, ? extends TargetObjectRef> deltaE, Delta<?, ?> deltaA) {
		ModelObjectDelta.Builder builder = Gadp.ModelObjectDelta.newBuilder()
				.addAllIndexRemoved(deltaE.getKeysRemoved())
				.addAllIndexAdded(deltaE.added.keySet())
				.addAllAttributeRemoved(deltaA.getKeysRemoved());
		for (Entry<String, ?> ent : deltaA.added.entrySet()) {
			builder.addAttributeAdded(makeAttribute(parent, ent));
		}
		return builder.build();
	}

	public static Gadp.Path makePath(List<String> path) {
		return Gadp.Path.newBuilder().addAllE(path).build();
	}

	public static Gadp.Path makePath(TargetObjectRef ref) {
		return makePath(ref.getPath());
	}

	public static Gadp.PathList makePathList(TargetObjectRefList<?> list) {
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

	public static Gadp.UpdateMode makeUpdateMode(TargetUpdateMode mode) {
		switch (mode) {
			case SOLICITED:
				return Gadp.UpdateMode.SOLICITED;
			case FIXED:
				return Gadp.UpdateMode.FIXED;
			case UNSOLICITED:
			default:
				return Gadp.UpdateMode.UNSOLICITED;
		}
	}

	public static TargetUpdateMode getUpdateMode(Gadp.UpdateMode mode) {
		switch (mode) {
			case FIXED:
				return TargetUpdateMode.FIXED;
			case SOLICITED:
				return TargetUpdateMode.SOLICITED;
			case UNSOLICITED:
			default:
				return TargetUpdateMode.UNSOLICITED;
		}
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
			case VT_UPDATE_MODE:
				return TargetUpdateMode.class;
			case VT_PATH:
				return TargetObjectRef.class;
			case VT_PATH_LIST:
				return TargetObjectRefList.class;
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
		if (type == TargetUpdateMode.class) {
			return Gadp.ValueType.VT_UPDATE_MODE;
		}
		if (type == TargetObjectRef.class) {
			return Gadp.ValueType.VT_PATH;
		}
		if (type == TargetObjectRefList.class) {
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
		else if (value instanceof TargetUpdateMode) {
			b.setUpdateModeValue(makeUpdateMode((TargetUpdateMode) value));
		}
		else if (value instanceof TargetParameterMap) {
			b.setParametersValue(makeParameterList((TargetParameterMap) value));
		}
		else if (path != null && getTargetObjectNonLink(path, value) != null) {
			// This case MUST precede TargetObjectRef
			b.setObjectStub(Gadp.ModelObjectStub.getDefaultInstance());
			// NOTE: Never produce info. That is a special case for object retrieval.
		}
		else if (value instanceof TargetObjectRef) {
			b.setPathValue(makePath((TargetObjectRef) value));
		}
		else if (value instanceof TargetObjectRefList) {
			b.setPathListValue(makePathList((TargetObjectRefList<?>) value));
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

	public static Gadp.Argument makeArgument(Map.Entry<String, ?> argument) {
		return Gadp.Argument.newBuilder()
				.setName(argument.getKey())
				.setValue(makeValue(null, argument.getValue()))
				.build();
	}

	public static Gadp.Attribute makeAttribute(TargetObject parent, Map.Entry<String, ?> ent) {
		return Gadp.Attribute.newBuilder()
				.setName(ent.getKey())
				.setValue(
					makeValue(PathUtils.extend(parent.getPath(), ent.getKey()), ent.getValue()))
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
			case UPDATE_MODE_VALUE:
				return getUpdateMode(value.getUpdateModeValue());
			case PARAMETERS_VALUE:
				return getParameters(model, value.getParametersValue());
			case PATH_VALUE:
				return model.createRef(value.getPathValue().getEList());
			case PATH_LIST_VALUE:
				return getRefList(model, value.getPathListValue());
			case OBJECT_INFO:
				Msg.error(GadpValueUtils.class, "ObjectInfo requires special treatment:" + value);
				return model.createRef(path);
			case OBJECT_STUB:
				return model.createRef(path);
			case TYPE_VALUE:
				return getValueType(value.getTypeValue());
			case SPEC_NOT_SET:
				return null;
			default:
				Msg.error(GadpValueUtils.class, "Got unknown value type: " + value);
				return null;
		}
	}

	public static Object getAttributeValue(TargetObject object, Gadp.Attribute attr) {
		return getValue(object.getModel(), PathUtils.extend(object.getPath(), attr.getName()),
			attr.getValue());
	}

	public static Map<String, Object> getAttributeMap(TargetObject object,
			List<Gadp.Attribute> list) {
		Map<String, Object> result = new LinkedHashMap<>();
		for (Gadp.Attribute attr : list) {
			if (result.put(attr.getName(),
				GadpValueUtils.getAttributeValue(object, attr)) != null) {
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

	public static List<Gadp.Argument> makeArguments(Map<String, ?> arguments) {
		return arguments.entrySet()
				.stream()
				.map(ent -> makeArgument(ent))
				.collect(Collectors.toList());
	}

	public static Map<String, TargetObjectRef> getElementMap(TargetObject parent,
			List<String> indices) {
		Map<String, TargetObjectRef> result = new LinkedHashMap<>();
		for (String index : indices) {
			result.put(index,
				parent.getModel().createRef(PathUtils.index(parent.getPath(), index)));
		}
		return result;
	}

	public static Map<String, ?> getArguments(DebuggerObjectModel model,
			List<Gadp.Argument> arguments) {
		return arguments.stream()
				.collect(
					Collectors.toMap(a -> a.getName(), a -> getValue(model, null, a.getValue())));
	}
}
