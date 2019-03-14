/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.lang;

import ghidra.program.model.address.Address;

import java.util.*;

public class RegisterTranslator {
	private static Comparator<Register> registerSizeComparator = new Comparator<Register>() {
		public int compare(Register r1, Register r2) {
			// Used for sorting largest to smallest
			return r2.getBitLength() - r1.getBitLength();
		}
	};

	private Register[] oldRegs;
	private Register[] newRegs;

	private HashMap<Integer, List<Register>> oldRegisterMap;
	private HashMap<Integer, List<Register>> newRegisterMap;
	private HashMap<String, Register> oldRegisterNameMap;
	private HashMap<String, Register> newRegisterNameMap;

	public RegisterTranslator(Language oldLang, Language newLang) {
		oldRegs = oldLang.getRegisters();
		newRegs = newLang.getRegisters();
		this.oldRegisterMap = buildOffsetMap(oldRegs);
		this.newRegisterMap = buildOffsetMap(newRegs);
		oldRegisterNameMap = buildNameMap(oldRegs);
		newRegisterNameMap = buildNameMap(newRegs);
	}

	private HashMap<Integer, List<Register>> buildOffsetMap(Register[] registers) {
		HashMap<Integer, List<Register>> offsetMap = new HashMap<Integer, List<Register>>();
		for (Register register : registers) {
			Address addr = register.getAddress();
			// Must disregard registers which are not in the "register" anmed space
			// since these would never have been encoded/decoded properly by the addressMap
			if (!addr.isRegisterAddress() ||
				!register.getAddressSpace().getName().equalsIgnoreCase("register")) {
				continue;
			}
			Integer offset = (int) addr.getOffset();
			List<Register> registerList = offsetMap.get(offset);
			if (registerList == null) {
				registerList = new ArrayList<Register>();
				offsetMap.put(offset, registerList);
			}
			registerList.add(register);
		}
		for (List<Register> registerList : offsetMap.values()) {
			Collections.sort(registerList, registerSizeComparator);
		}
		return offsetMap;
	}

	private HashMap<String, Register> buildNameMap(Register[] regs) {
		HashMap<String, Register> map = new HashMap<String, Register>();
		for (Register r : regs) {
			map.put(r.getName().toUpperCase(), r);
		}
		return map;
	}

	public Register getOldRegister(int offset, int size) {
		List<Register> list = oldRegisterMap.get(offset);
		if (list != null) {
			if (size == 0) {
				return list.get(0);
			}
			for (int i = list.size() - 1; i >= 0; i--) {
				Register reg = list.get(i);
				if (reg.getMinimumByteSize() >= size) {
					return reg;
				}
			}
		}
		return null;
	}

	public Register getNewRegister(int offset, int size) {
		List<Register> list = newRegisterMap.get(offset);
		if (list != null) {
			if (size == 0) {
				return list.get(0);
			}
			for (int i = list.size() - 1; i >= 0; i--) {
				Register reg = list.get(i);
				if (reg.getMinimumByteSize() >= size) {
					return reg;
				}
			}
		}
		return null;
	}

	public Register getNewRegister(Register oldReg) {
		return newRegisterNameMap.get(oldReg.getName().toUpperCase());
	}

	public Register getOldRegister(Register newReg) {
		return oldRegisterNameMap.get(newReg.getName().toUpperCase());
	}

	public Register[] getNewRegisters() {
		return newRegs;
	}

}
