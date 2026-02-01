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
package ghidra.app.plugin.core.debug.service.tracermi;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.program.model.address.*;
import ghidra.rmi.trace.TraceRmi.*;
import ghidra.util.NumericUtilities;

public interface ValueDecoder {
	ValueDecoder DEFAULT = new ValueDecoder() {};
	ValueDecoder DISPLAY = new ValueDecoder() {
		final Map<String, AddressSpace> spaces = new HashMap<>();

		private AddressSpace getSpace(String space) {
			return spaces.computeIfAbsent(space, name -> {
				return new GenericAddressSpace(name, 64, AddressSpace.TYPE_RAM, 0);
			});
		}

		@Override
		public Address toAddress(Addr addr, boolean required) {
			AddressSpace space = getSpace(addr.getSpace());
			return space.getAddress(addr.getOffset());
		}

		@Override
		public AddressRange toRange(AddrRange range, boolean required) {
			AddressSpace space = getSpace(range.getSpace());
			Address min = space.getAddress(range.getOffset());
			Address max = space.getAddress(range.getOffset() + range.getExtend());
			return new AddressRangeImpl(min, max);
		}

		@Override
		public Object getObject(ObjDesc desc, boolean required) {
			return "<Object id=%d path=%s>".formatted(desc.getId(), desc.getPath().getPath());
		}

		@Override
		public Object getObject(ObjSpec spec, boolean required) {
			return switch (spec.getKeyCase()) {
				case KEY_NOT_SET -> "<ERROR: No key>";
				case ID -> "<Object id=%d>".formatted(spec.getId());
				case PATH -> "<Object path=%s>".formatted(spec.getPath());
				default -> "<ERROR: default>";
			};
		}

		@Override
		public Object toValue(Value value) {
			Object obj = ValueDecoder.super.toValue(value);
			if (obj instanceof byte[] va) {
				return NumericUtilities.convertBytesToString(va, ":");
			}
			return obj;
		}
	};

	default Address toAddress(Addr addr, boolean required) {
		if (required) {
			throw new IllegalStateException("Address requires a trace for context");
		}
		return null;
	}

	default AddressRange toRange(AddrRange range, boolean required) {
		if (required) {
			throw new IllegalStateException("AddressRange requires a trace for context");
		}
		return null;
	}

	default Object getObject(ObjSpec spec, boolean required) {
		if (required) {
			throw new IllegalStateException("TraceObject requires a trace for context");
		}
		return null;
	}

	default Object getObject(ObjDesc desc, boolean required) {
		if (required) {
			throw new IllegalStateException("TraceObject requires a trace for context");
		}
		return null;
	}

	default Object toValue(Value value) {
		return switch (value.getValueCase()) {
			case NULL_VALUE -> null;
			case BOOL_VALUE -> value.getBoolValue();
			case BYTE_VALUE -> (byte) value.getByteValue();
			case CHAR_VALUE -> (char) value.getCharValue();
			case SHORT_VALUE -> (short) value.getShortValue();
			case INT_VALUE -> value.getIntValue();
			case LONG_VALUE -> value.getLongValue();
			case STRING_VALUE -> value.getStringValue();
			case BOOL_ARR_VALUE -> ArrayUtils.toPrimitive(
				value.getBoolArrValue().getArrList().stream().toArray(Boolean[]::new));
			case BYTES_VALUE -> value.getBytesValue().toByteArray();
			case CHAR_ARR_VALUE -> value.getCharArrValue().toCharArray();
			case SHORT_ARR_VALUE -> ArrayUtils.toPrimitive(
				value.getShortArrValue()
						.getArrList()
						.stream()
						.map(Integer::shortValue)
						.toArray(Short[]::new));
			case INT_ARR_VALUE -> value.getIntArrValue()
					.getArrList()
					.stream()
					.mapToInt(Integer::intValue)
					.toArray();
			case LONG_ARR_VALUE -> value.getLongArrValue()
					.getArrList()
					.stream()
					.mapToLong(Long::longValue)
					.toArray();
			case STRING_ARR_VALUE -> value.getStringArrValue()
					.getArrList()
					.toArray(String[]::new);
			case ADDRESS_VALUE -> toAddress(value.getAddressValue(), true);
			case RANGE_VALUE -> toRange(value.getRangeValue(), true);
			case CHILD_SPEC -> getObject(value.getChildSpec(), true);
			case CHILD_DESC -> getObject(value.getChildDesc(), true);
			default -> throw new AssertionError("Unrecognized value: " + value);
		};
	}
}
