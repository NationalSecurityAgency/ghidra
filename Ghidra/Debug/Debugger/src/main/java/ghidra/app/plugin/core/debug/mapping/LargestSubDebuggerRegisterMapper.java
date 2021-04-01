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
package ghidra.app.plugin.core.debug.mapping;

import java.math.BigInteger;
import java.util.*;

import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.target.TargetRegisterContainer;
import ghidra.dbg.util.ConversionUtils;
import ghidra.program.model.lang.*;
import ghidra.util.Msg;

public class LargestSubDebuggerRegisterMapper extends DefaultDebuggerRegisterMapper {
	protected static final Comparator<Register> LENGTH_COMPARATOR =
		Comparator.comparing(Register::getBitLength);
	protected Map<String, Register> allLanguageRegs = new LinkedHashMap<>();
	protected Map<Register, TreeSet<Register>> present = new HashMap<>();

	public LargestSubDebuggerRegisterMapper(CompilerSpec cSpec,
			TargetRegisterContainer targetRegContainer, boolean caseSensitive) {
		super(cSpec, targetRegContainer, caseSensitive);

		for (Register lReg : cSpec.getLanguage().getRegisters()) {
			allLanguageRegs.put(normalizeName(lReg.getName()), lReg);
		}
	}

	@Override
	protected boolean testTraceRegister(Register lReg) {
		return true;
	}

	@Override
	protected synchronized Register considerRegister(String index) {
		Register lReg = super.considerRegister(index);
		if (lReg == null) {
			return null;
		}
		//synchronized (present) {
		present.computeIfAbsent(lReg.getBaseRegister(), r -> new TreeSet<>(LENGTH_COMPARATOR))
				.add(lReg);
		//}
		return lReg;
	}

	@Override
	protected synchronized Register considerRegister(TargetRegister tReg) {
		Register lReg = super.considerRegister(tReg);
		if (lReg == null) {
			return null;
		}
		//synchronized (present) {
		present.computeIfAbsent(lReg.getBaseRegister(), r -> new TreeSet<>(LENGTH_COMPARATOR))
				.add(lReg);
		//}
		return lReg;
	}

	@Override
	protected synchronized Register removeRegister(TargetRegister tReg) {
		Register lReg = super.removeRegister(tReg);
		//synchronized (present) {
		if (lReg == null) {
			return null;
		}
		Register lbReg = lReg.getBaseRegister();
		TreeSet<Register> set = present.get(lbReg);
		set.remove(lReg);
		if (set.isEmpty()) {
			present.remove(lbReg);
		}
		//}
		return lReg;
	}

	@Override
	public synchronized Register getTraceRegister(String name) {
		Register lReg = allLanguageRegs.get(normalizeName(name));
		if (lReg == null || !present.containsKey(lReg)) {
			return null;
		}
		return lReg;
	}

	@Override
	public synchronized Map.Entry<String, byte[]> traceToTarget(RegisterValue registerValue) {
		Register lbReg = registerValue.getRegister();
		if (!lbReg.isBaseRegister()) {
			throw new IllegalArgumentException();
		}
		TreeSet<Register> subs = present.get(lbReg);
		if (subs == null) {
			return null;
		}
		Register lReg = subs.last(); // largest
		RegisterValue subValue = registerValue.getRegisterValue(lReg);
		TargetRegister tReg = targetRegs.get(normalizeName(lReg.getName()));
		if (tReg == null) {
			return null;
		}
		return Map.entry(tReg.getIndex(), ConversionUtils
				.bigIntegerToBytes(lReg.getMinimumByteSize(), subValue.getUnsignedValue()));
	}

	@Override
	public synchronized TargetRegister traceToTarget(Register lbReg) {
		TreeSet<Register> subs = present.get(lbReg);
		if (subs == null) { // Not a base reg, or not known
			return null;
		}
		Register lReg = subs.last(); // largest
		return targetRegs.get(normalizeName(lReg.getName()));
	}

	@Override
	public synchronized RegisterValue targetToTrace(String tRegName, byte[] value) {
		if (value == null) {
			return null;
		}
		Register lReg = languageRegs.get(normalizeName(tRegName));
		if (lReg == null) {
			lReg = considerRegister(tRegName);
			if (lReg == null) {
				return null;
			}
		}
		Register lbReg = lReg.getBaseRegister();
		TreeSet<Register> subs = present.get(lbReg);
		if (subs == null) {
			return null;
		}
		if (lReg != subs.last()) {
			/**
			 * Neither the recorder nor the UI ought to have read or written this register, since it
			 * is not the "largest" known. But apparently something did, so it's possible there are
			 * two names in the cache belonging to the same structural register whose values don't
			 * necessarily agree. This can happen, e.g., if "EAX" is written but "RAX" is already in
			 * the cache. The next read for "RAX" will likely return a stale value. Granted, the
			 * cache is invalidated fairly frequently -- every step, at least. Nevertheless, this
			 * should not have happened.
			 */
			Msg.warn(this, "Potential register cache aliasing: " + lReg + " vs " + subs.last());
			/**
			 * After testing, there is a problem with data truncation. If, e.g., EAX is sent,
			 * followed by AX, and we expand to fill RAX, the we're going to truncate the upper 16
			 * bits of EAX :( . To avoid this, we'll only map the largest register from target to
			 * trace. We'll still warn as a courtesy, but we'll abort the mapping.
			 */
			return null;
		}
		/**
		 * TODO: A mapping with masks may be useful in the future, but as it is, the trace database
		 * will reject it. Furthermore, we'd still want to mark the whole base register is known,
		 * which is not intuitive, and makes me worry about that method.
		 */
		// return new RegisterValue(lReg, new BigInteger(1,value)).getBaseRegisterValue();
		// Pad zeroes in the rest of base register
		RegisterValue lbVal = new RegisterValue(lbReg, BigInteger.ZERO);
		return lbVal.assign(lReg, new BigInteger(1, value));
	}

	@Override
	public RegisterValue targetToTrace(TargetRegister tReg, byte[] value) {
		return targetToTrace(tReg.getIndex(), value);
	}

	@Override
	public synchronized Register targetToTrace(TargetRegister tReg) {
		Register lReg = languageRegs.get(normalizeName(tReg.getIndex()));
		if (lReg == null) {
			return null;
		}
		Register lbReg = lReg.getBaseRegister();
		TreeSet<Register> subs = present.get(lbReg);
		if (subs == null) {
			return null;
		}
		if (lReg != subs.last()) {
			return null;
		}
		return lbReg;
	}

	@Override
	public synchronized Set<Register> getRegistersOnTarget() {
		return Set.copyOf(present.keySet());
	}
}
