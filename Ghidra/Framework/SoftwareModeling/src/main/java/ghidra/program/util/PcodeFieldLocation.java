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
package ghidra.program.util;

import java.util.*;

import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class PcodeFieldLocation extends ProgramLocation {

	private List<String> pcodeStrings;

	public PcodeFieldLocation(Program program, Address addr, List<String> pcodeStrings, int row,
			int charOffset) {
		super(program, addr, row, 0, charOffset);
		this.pcodeStrings = pcodeStrings;
	}

	/**
	 * Get the row within a group of pcode strings.
	 */
	public PcodeFieldLocation() {
		// for deserialization
	}

	public List<String> getPcodeStrings() {
		return Collections.unmodifiableList(pcodeStrings);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((pcodeStrings == null) ? 0 : pcodeStrings.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		PcodeFieldLocation other = (PcodeFieldLocation) obj;
		if (pcodeStrings == null) {
			if (other.pcodeStrings != null)
				return false;
		}
		else if (!pcodeStrings.equals(other.pcodeStrings))
			return false;
		return true;
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putStrings("_PCODE_STRINGS", pcodeStrings.toArray(new String[pcodeStrings.size()]));
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);

		String[] strings = obj.getStrings("_PCODE_STRINGS", new String[0]);
		pcodeStrings = new ArrayList<String>(strings.length);
		for (String string : strings) {
			pcodeStrings.add(string);
		}
	}

	@Override
	public String toString() {
		return super.toString() + ", Pcode sample: " + getPcodeSample();
	}

	private String getPcodeSample() {
		if (pcodeStrings.size() == 0) {
			return "<no pcode>";
		}
		return pcodeStrings.get(0);
	}
}
