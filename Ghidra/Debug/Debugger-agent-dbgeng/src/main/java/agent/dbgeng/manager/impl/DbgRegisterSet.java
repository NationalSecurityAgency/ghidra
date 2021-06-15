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
package agent.dbgeng.manager.impl;

import java.util.*;

public class DbgRegisterSet extends AbstractSet<DbgRegister> {
	private final Map<String, DbgRegister> byName = new HashMap<>();
	private final Map<Integer, DbgRegister> byNumber = new TreeMap<>();

	/**
	 * Construct a set from the given collection
	 * 
	 * Note that regs need not be presented in any particular order; however, there must be at most
	 * one register per number. Otherwise, there may be undefined behavior.
	 * 
	 * @param regs the registers to index
	 */
	public DbgRegisterSet(Collection<DbgRegister> regs) {
		for (DbgRegister r : regs) {
			byName.put(r.getName(), r);
			byNumber.put(r.getNumber(), r);
		}
	}

	/**
	 * Get a register by name
	 * 
	 * @param name the name
	 * @return the register
	 */
	public DbgRegister get(String name) {
		return byName.get(name);
	}

	/**
	 * Get a register by number
	 * 
	 * @param number the number
	 * @return the register
	 */
	public DbgRegister get(int number) {
		return byNumber.get(number);
	}

	@Override
	public Iterator<DbgRegister> iterator() {
		return byNumber.values().iterator();
	}

	@Override
	public int size() {
		return byNumber.size();
	}
}
