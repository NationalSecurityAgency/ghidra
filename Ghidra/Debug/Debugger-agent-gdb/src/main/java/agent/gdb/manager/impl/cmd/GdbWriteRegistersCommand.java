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
import java.util.Map;

import org.apache.commons.lang3.ArrayUtils;

import agent.gdb.manager.GdbRegister;
import agent.gdb.manager.GdbContextualOperations;
import agent.gdb.manager.evt.GdbCommandDoneEvent;
import agent.gdb.manager.impl.*;
import ghidra.dbg.util.ConversionUtils;

/**
 * Implementation of {@link GdbContextualOperations#writeRegisters(Map)}
 */
public class GdbWriteRegistersCommand extends AbstractGdbCommandWithThreadAndFrameId<Void> {
	protected static final BigInteger UINT128_MAX =
		BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);

	private final GdbThreadImpl thread;
	private final Map<GdbRegister, BigInteger> regVals;

	public GdbWriteRegistersCommand(GdbManagerImpl manager, GdbThreadImpl thread, Integer frameId,
			Map<GdbRegister, BigInteger> regVals) {
		super(manager, thread.getId(), frameId);
		this.thread = thread;

		this.regVals = regVals;
	}

	protected void encodeInt8Array(StringBuilder b, BigInteger value, int bytes) {
		ByteOrder endianness = thread.getInferior().getEndianness();
		byte[] arr = ConversionUtils.bigIntegerToBytes(bytes, value);
		if (endianness != ByteOrder.BIG_ENDIAN) {
			ArrayUtils.reverse(arr);
		}
		boolean first = true;
		for (int i = 0; i < bytes; i++) {
			if (first) {
				first = false;
			}
			else {
				b.append(',');
			}
			int v = arr[i] & 0xff;
			b.append(v);
		}
	}

	@Override
	// Opting for console command, as -data-write-register-values is buggy
	protected String encode(String threadPart, String framePart) {
		StringBuilder b = new StringBuilder();
		b.append("-interpreter-exec");
		b.append(threadPart);
		b.append(framePart);
		b.append(" console \"set");
		boolean first = true;
		for (Map.Entry<GdbRegister, BigInteger> ent : regVals.entrySet()) {
			if (first) {
				b.append(' ');
				first = false;
			}
			else {
				b.append(',');
			}
			b.append('$');
			GdbRegister reg = ent.getKey();
			b.append(reg.getName());

			BigInteger value = ent.getValue();
			//if the register is 16 or fewer bytes, just use the name
			if (reg.getSize() <= 16) {
				b.append('=');
				b.append(value.toString());
			}
			//if the register is more than 16 bytes use gdb's struct syntax
			//note: this only works for x64
			else {
				b.append(".v");
				b.append(reg.getSize());
				b.append("_int8={");
				encodeInt8Array(b, value, reg.getSize());
				b.append('}');
			}
		}
		b.append("\"");
		return b.toString();
	}

	// This command can't seem to take larger than uint128
	// Attempting vector-ish stuff here may cause GDB to segfault
	protected String encodeForMi(String threadPart, String framePart) {
		StringBuilder b = new StringBuilder();
		b.append("-data-write-register-values");
		b.append(threadPart);
		b.append(framePart);
		b.append(" x");
		for (Map.Entry<GdbRegister, BigInteger> ent : regVals.entrySet()) {
			b.append(" ");
			b.append(ent.getKey().getNumber());
			b.append(" 0x");
			b.append(ent.getValue().toString(16));
		}
		return b.toString();
	}

	@Override
	public Void complete(GdbPendingCommand<?> pending) {
		pending.checkCompletion(GdbCommandDoneEvent.class);
		return null;
	}
}
