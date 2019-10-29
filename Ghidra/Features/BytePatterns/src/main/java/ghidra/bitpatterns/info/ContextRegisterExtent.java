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
 * A class for representing accumulated context register information.
 */
public class ContextRegisterExtent {

	private Set<String> contextRegisters;//names of the context registers
	private Map<String, Set<BigInteger>> regsToValues;//for each register, a list of values it can take

	/**
	 * Create a empty {@link ContextRegisterExtent}
	 */
	public ContextRegisterExtent() {
		contextRegisters = new HashSet<String>();
		regsToValues = new HashMap<String, Set<BigInteger>>();
	}

	/**
	 * Accumulates the information in each element of {@code contextRegisterInfo} into the extent.
	 * @param contextRegisterInfo
	 */
	public void addContextInfo(List<ContextRegisterInfo> contextRegisterInfo) {
		if ((contextRegisterInfo == null) || (contextRegisterInfo.isEmpty())) {
			return;
		}
		for (ContextRegisterInfo cRegInfo : contextRegisterInfo) {
			addRegisterAndValue(cRegInfo.getContextRegister(), cRegInfo.getValue());
		}
	}

	private void addRegisterAndValue(String register, BigInteger value) {
		if (!contextRegisters.contains(register)) {
			contextRegisters.add(register);
			Set<BigInteger> valueSet = new HashSet<BigInteger>();
			regsToValues.put(register, valueSet);
		}
		regsToValues.get(register).add(value);
	}

	/**
	 * Returns an alphabetized list of context registers.
	 * @return the list
	 */
	public List<String> getContextRegisters() {
		List<String> contextRegisterList = new ArrayList<String>(contextRegisters.size());
		contextRegisterList.addAll(contextRegisters);
		Collections.sort(contextRegisterList);
		return contextRegisterList;
	}

	/**
	 * Returns a list of values the register takes in the extent.
	 * @param register - the register to query against the extent
	 * @return - a list of values (may be empty);
	 */
	public List<BigInteger> getValuesForRegister(String register) {
		List<BigInteger> valuesList = new ArrayList<BigInteger>();
		Set<BigInteger> values = regsToValues.get(register);
		if ((register != null) && (values != null)) {
			valuesList.addAll(values);
			Collections.sort(valuesList);
		}
		return valuesList;
	}

	@Override
	public String toString() {
		if (getContextRegisters().isEmpty()) {
			return "";
		}
		StringBuilder sb = new StringBuilder();
		List<String> registers = getContextRegisters();
		for (String register : registers) {
			sb.append("Register: ");
			sb.append(register);
			sb.append("\n");
			sb.append("Values: ");
			List<BigInteger> values = getValuesForRegister(register);
			for (int i = 0; i < values.size(); ++i) {
				sb.append(values.get(i));
				if (i != (values.size() - 1)) {
					sb.append(", ");
				}
				else {
					sb.append("\n\n");
				}
			}
		}
		return sb.toString();
	}

}
