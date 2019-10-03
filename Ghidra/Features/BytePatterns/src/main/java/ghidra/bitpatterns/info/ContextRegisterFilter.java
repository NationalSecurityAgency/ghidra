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
package ghidra.bitpatterns.info;

import java.math.BigInteger;
import java.util.*;

/**
 * Objects of this class are used to filter lists of {@link ContextRegisterInfo}s
 */
public class ContextRegisterFilter {

	private Set<String> contextRegisters;//the context registers under consideration
	private Map<String, BigInteger> values;//for each context register, the value the filter allows

	public ContextRegisterFilter() {
		contextRegisters = new HashSet<String>();
		values = new HashMap<String, BigInteger>();
	}

	/**
	 * Add a pair (register,value) to the filter.
	 * 
	 * @param contextRegister - the context register
	 * @param value           - the value the filter allows
	 * @throws IllegalStateException if you add a value for a register that already has a value in the filter
	 */
	public void addRegAndValueToFilter(String contextRegister, BigInteger value) {
		if (contextRegisters.contains(contextRegister)) {
			throw new IllegalStateException("Filter can have only one value per register!");
		}
		contextRegisters.add(contextRegister);
		values.put(contextRegister, value);
	}

	/**
	 * Determines whether a list of {@link ContextRegisterInfo} objects passes the filter.
	 * 
	 * @param contextRegisterInfos
	 * @return {@code true} precisely when each {@link ContextRegisterInfo} in {@link ContextRegisterInfos} passes
	 * the filter.
	 */
	public boolean allows(List<ContextRegisterInfo> contextRegisterInfos) {
		for (ContextRegisterInfo cInfo : contextRegisterInfos) {
			if (contextRegisters.contains(cInfo.getContextRegister())) {
				if (!values.get(cInfo.getContextRegister()).equals(cInfo.getValue())) {
					return false;
				}
			}
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Context Register Filter: \n");
		for (String cReg : contextRegisters) {
			sb.append(cReg);
			sb.append(": ");
			sb.append(values.get(cReg).toString());
			sb.append("\n");
		}
		sb.append("\n");
		return sb.toString();
	}

	/**
	 * Returns a compact string representation of the filter for displaying in rows of a table
	 * @return string representation
	 */
	public String getCompactString() {
		StringBuilder sb = new StringBuilder();
		String[] registers = contextRegisters.toArray(new String[0]);
		for (int i = 0, max = registers.length; i < max; ++i) {
			sb.append(registers[i]);
			sb.append("=");
			sb.append(values.get(registers[i]).toString());
			if (i < max - 1) {
				sb.append(";");
			}
		}
		return sb.toString();
	}

	@Override
	public int hashCode() {
		int hash = 17;
		hash = 31 * hash + contextRegisters.hashCode();
		hash = 31 * hash + values.hashCode();
		return hash;
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof ContextRegisterFilter)) {
			return false;
		}
		ContextRegisterFilter otherFilter = (ContextRegisterFilter) o;
		if (!otherFilter.contextRegisters.equals(contextRegisters)) {
			return false;
		}
		if (!otherFilter.values.equals(values)) {
			return false;
		}
		return true;
	}

	/**
	 * Get the filter map
	 * @return the map
	 */
	public Map<String, BigInteger> getValueMap() {
		return values;
	}

}
