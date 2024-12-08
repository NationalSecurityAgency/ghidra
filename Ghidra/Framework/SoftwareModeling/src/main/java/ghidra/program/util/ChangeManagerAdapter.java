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

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;

/**
 * Empty implementation for a ChangeManager.
 */
public class ChangeManagerAdapter implements ChangeManager {

	@Override
	public void setPropertyChanged(String propertyName, Address codeUnitAddr, Object oldValue,
			Object newValue) {
		// Default implementation does nothing.
	}

	@Override
	public void setPropertyRangeRemoved(String propertyName, Address start, Address end) {
		// Default implementation does nothing.
	}

	@Override
	public void setRegisterValuesChanged(Register register, Address start, Address end) {
		// Default implementation does nothing.
	}

	@Override
	public void setChanged(ProgramEvent event, Object oldValue, Object newValue) {
		// Default implementation does nothing.
	}

	@Override
	public void setChanged(ProgramEvent event, Address start, Address end, Object oldValue,
			Object newValue) {
		// Default implementation does nothing.
	}

	@Override
	public void setObjChanged(ProgramEvent event, Object affected, Object oldValue,
			Object newValue) {
		// Default implementation does nothing.
	}

	@Override
	public void setObjChanged(ProgramEvent eventType, Address addr, Object affected,
			Object oldValue, Object newValue) {
		// Default implementation does nothing.
	}

}
