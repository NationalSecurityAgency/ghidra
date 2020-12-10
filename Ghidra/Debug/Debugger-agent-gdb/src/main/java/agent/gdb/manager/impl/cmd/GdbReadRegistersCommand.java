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

	protected BigInteger parseAndFindInteger(String val, int byteCount) throws GdbParseError {
		ByteOrder endianness = thread.getInferior().getEndianness();
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
					List<Integer> int8l = int8a.expectInts();
					byte[] ordered = new byte[int8l.size()];
					int i = endianness == ByteOrder.BIG_ENDIAN ? 0 : ordered.length - 1;
					int step = endianness == ByteOrder.BIG_ENDIAN ? 1 : -1;
					for (int b : int8l) {
						ordered[i] = (byte) b;
						i += step;
					}
					return new BigInteger(1, ordered);
				}
			}
		}
		throw new AssertionError("Expected an int, or a union containing an int. Got " + val);
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
					"Could not figure register value for [" + number + "] = " + value, e);
			}
		}
		return result;
	}
}
