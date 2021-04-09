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
package agent.gdb.manager.impl.cmd;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.stream.Collectors;

import agent.gdb.manager.GdbRegister;
import agent.gdb.manager.GdbStackFrameOperations;
import agent.gdb.manager.evt.AbstractGdbCompletedCommandEvent;
import agent.gdb.manager.evt.GdbCommandDoneEvent;
import agent.gdb.manager.impl.*;
import agent.gdb.manager.parsing.GdbCValueParser;
import agent.gdb.manager.parsing.GdbCValueParser.*;
import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;
import ghidra.pcode.utils.Utils;
import ghidra.util.Msg;

/**
 * Implementation of {@link GdbStackFrameOperations#readRegisters(Set)}
 */
public class GdbReadRegistersCommand
		extends AbstractGdbCommandWithThreadAndFrameId<Map<GdbRegister, BigInteger>> {
	protected static final Set<String> BYTE_ARRAY_KEYS = Set.of(
		"v1_int8", "v2_int8", "v4_int8", "v8_int8", "v16_int8", "v32_int8", "v64_int8", // Observed on i386:x86-64
		"u8" // Observed on armv7
	);
	private final Set<GdbRegister> regs;
	private final GdbThreadImpl thread;

	public GdbReadRegistersCommand(GdbManagerImpl manager, GdbThreadImpl thread, Integer frameId,
			Set<GdbRegister> regs) {
		super(manager, thread.getId(), frameId);
		this.thread = thread;
		this.regs = regs;
	}

	@Override
	protected String encode(String threadPart, String framePart) {
		if (regs.isEmpty()) {
			return "-interpreter-exec console echo";
		}
		StringBuilder b = new StringBuilder();
		b.append("-data-list-register-values");
		b.append(threadPart);
		b.append(framePart);
		b.append(" x");
		for (GdbRegister r : regs) {
			b.append(" ");
			b.append(r.getNumber());
		}
		return b.toString();
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (evt instanceof AbstractGdbCompletedCommandEvent) {
			pending.claim(evt);
			return true;
		}
		return false;
	}

	protected BigInteger packElements(GdbArrayValue av, int byteCount, int bytesPer,
			ByteOrder endianness) {
		assert bytesPer * av.size() == byteCount;
		List<BigInteger> elems = av.expectBigInts();
		byte[] packed = new byte[byteCount];
		ByteBuffer buf = ByteBuffer.wrap(packed);
		int i = endianness == ByteOrder.BIG_ENDIAN ? 0 : packed.length - bytesPer;
		int step = endianness == ByteOrder.BIG_ENDIAN ? bytesPer : -bytesPer;
		for (BigInteger elem : elems) {
			buf.position(i);
			switch (bytesPer) {
				case 1:
					buf.put(elem.byteValue());
					break;
				case 2:
					buf.putShort(elem.shortValue());
					break;
				case 4:
					buf.putInt(elem.intValue());
					break;
				case 8:
					buf.putLong(elem.longValue());
					break;
				default:
					buf.put(Utils.bigIntegerToBytes(elem, bytesPer, true));
					break;
			}
			i += step;
		}
		return new BigInteger(1, packed);
	}

	protected BigInteger parseAndFindInteger(String val, int byteCount) throws GdbParseError {
		ByteOrder endianness = thread.getInferior().getEndianness();
		if (val.contains("lbound")) {
			/**
			 * TODO: This might be useful information, but I've only ever seen
			 * lbound=0x0,ubound=0xfff...fff} : size -1, so I'm just going to call this 0 and spare
			 * the log a mess.
			 */
			return BigInteger.ZERO;
		}
		GdbCValue value = GdbCValueParser.parseValue(val);
		if (value instanceof GdbIntValue) {
			GdbIntValue iv = (GdbIntValue) value;
			return iv.getValue();
		}
		if (value instanceof GdbCompositeValue) {
			GdbCompositeValue cv = (GdbCompositeValue) value;
			for (GdbCValue v : cv.values()) {
				if (v instanceof GdbIntValue) {
					GdbIntValue iv = (GdbIntValue) v;
					return iv.getValue();
				}
			}
			for (Map.Entry<String, GdbCValue> ent : cv.entrySet()) {
				if (BYTE_ARRAY_KEYS.contains(ent.getKey())) {
					GdbCValue int8v = ent.getValue();
					if (!(int8v instanceof GdbArrayValue)) {
						throw new AssertionError("Expected an array of ints for " + ent);
					}
					GdbArrayValue int8a = (GdbArrayValue) int8v;
					return packElements(int8a, byteCount, 1, endianness);
				}
			}
		}
		if (value instanceof GdbArrayValue) {
			GdbArrayValue av = (GdbArrayValue) value;
			if (byteCount % av.size() != 0) {
				throw new AssertionError("Cannot divide bytes evenly among vector elements. size=" +
					byteCount + ", value=" + val);
			}
			int bytesPer = byteCount / av.size();
			return packElements(av, byteCount, bytesPer, endianness);
		}
		throw new AssertionError(
			"Expected an int, a union containing an int, or an array. Got " + val);
	}

	@Override
	public Map<GdbRegister, BigInteger> complete(GdbPendingCommand<?> pending) {
		GdbCommandDoneEvent done = pending.checkCompletion(GdbCommandDoneEvent.class);
		if (regs.isEmpty()) {
			return Collections.emptyMap();
		}
		Map<Integer, GdbRegister> regsByNumber =
			regs.stream().collect(Collectors.toMap(GdbRegister::getNumber, r -> r));
		List<GdbMiFieldList> valueList = done.assumeRegisterValueList();
		Map<GdbRegister, BigInteger> result = new LinkedHashMap<>();
		for (GdbMiFieldList fields : valueList) {
			int number = Integer.parseInt(fields.getString("number"));
			String value = fields.getString("value");
			GdbRegister r = regsByNumber.get(number);
			if (r == null) {
				Msg.error(this, "GDB gave value for non-requested register: " + number);
				continue;
			}
			try {
				result.put(r, parseAndFindInteger(value, r.getSize()));
			}
			catch (GdbParseError | AssertionError e) {
				Msg.warn(this,
					"Could not figure register value for [" + number + "] = " + value/*, e*/);
			}
		}
		return result;
	}
}
