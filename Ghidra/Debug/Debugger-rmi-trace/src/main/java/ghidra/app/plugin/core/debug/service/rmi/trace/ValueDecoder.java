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
package ghidra.app.plugin.core.debug.service.rmi.trace;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.program.model.address.*;
import ghidra.rmi.trace.TraceRmi.*;

public interface ValueDecoder {
	ValueDecoder DEFAULT = new ValueDecoder() {};

	default Address toAddress(Addr addr, boolean required) {
		if (required) {
			throw new IllegalStateException("Address requires a trace for context");
		}
		return null;
	}

	default AddressRange toRange(AddrRange range, boolean required)
			throws AddressOverflowException {
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

	default Object toValue(Value value) throws AddressOverflowException {
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
