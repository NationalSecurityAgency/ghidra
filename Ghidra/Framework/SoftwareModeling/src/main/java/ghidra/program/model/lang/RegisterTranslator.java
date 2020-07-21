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
package ghidra.program.model.lang;

import java.util.*;

import ghidra.program.model.address.Address;

public class RegisterTranslator {
	private static Comparator<Register> registerSizeComparator = new Comparator<Register>() {
		@Override
		public int compare(Register r1, Register r2) {
			// Used for sorting largest to smallest
			return r2.getBitLength() - r1.getBitLength();
		}
	};

	private Language oldLang;
	private Language newLang;

	private HashMap<Integer, List<Register>> oldRegisterMap;
	private HashMap<Integer, List<Register>> newRegisterMap;

	public RegisterTranslator(Language oldLang, Language newLang) {
		this.oldLang = oldLang;
		this.newLang = newLang;
		this.oldRegisterMap = buildOffsetMap(oldLang.getRegisters());
		this.newRegisterMap = buildOffsetMap(newLang.getRegisters());
	}

	private HashMap<Integer, List<Register>> buildOffsetMap(List<Register> registers) {
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
		return newLang.getRegister(oldReg.getName());
	}

	public Register getOldRegister(Register newReg) {
		return oldLang.getRegister(newReg.getName());
	}

	public List<Register> getNewRegisters() {
		return newLang.getRegisters();
	}

}
