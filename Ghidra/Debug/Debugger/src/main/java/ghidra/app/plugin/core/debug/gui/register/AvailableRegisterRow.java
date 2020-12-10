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
package ghidra.app.plugin.core.debug.gui.register;

import java.util.Set;
import java.util.TreeSet;

import org.apache.commons.lang3.StringUtils;

import ghidra.program.model.lang.Register;

public class AvailableRegisterRow {
	private final int number;
	private final Register register;
	private final String contains;

	private boolean known;
	private boolean selected;

	public AvailableRegisterRow(int number, Register register) {
		this.number = number;
		this.register = register;
		this.contains = computeContains(); // Helps user search
	}

	protected String computeContains() {
		Set<String> descendants = new TreeSet<>();
		collectChildren(register, descendants);
		return StringUtils.join(descendants, ", ");
	}

	protected void collectChildren(Register reg, Set<String> set) {
		for (Register child : reg.getChildRegisters()) {
			set.add(child.getName());
			collectChildren(child, set);
		}
	}

	public Register getRegister() {
		return register;
	}

	public int getNumber() {
		return number;
	}

	public String getName() {
		return register.getName();
	}

	public int getBits() {
		return register.getBitLength();
	}

	public String getGroup() {
		String group = register.getGroup();
		if (group == null) {
			return "(none)";
		}
		return group;
	}

	public boolean isSelected() {
		return selected;
	}

	public void setSelected(boolean select) {
		this.selected = select;
	}

	public boolean isKnown() {
		return known;
	}

	// Note: not modifiable by table
	public void setKnown(boolean known) {
		this.known = known;
	}

	public String getContains() {
		return contains;
	}

	public String getParentName() {
		Register base = register.getBaseRegister();
		if (base == register || base == null) {
			return "";
		}
		return base.getName();
	}
}
