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
package ghidra.app.plugin.core.instructionsearch.model;

/**
 * Contains information about how to mask the associated address range.
 */
public class MaskSettings {

	private boolean maskAddresses = false;
	private boolean maskOperands = false;
	private boolean maskScalars = false;


	/**
	 * 
	 * @param maskAddresses
	 * @param maskOperands
	 * @param maskScalars
	 */
	public MaskSettings(boolean maskAddresses, boolean maskOperands, boolean maskScalars) {
		this.maskOperands = maskOperands;
		this.maskScalars = maskScalars;
		this.maskAddresses = maskAddresses;	
	}

	/**
	 * 
	 */
	public void clear() {
		maskOperands = false;
		maskScalars = false;
		maskAddresses = false;
	}

	public boolean isMaskAddresses() {
		return maskAddresses;
	}

	public void setMaskAddresses(boolean maskAddresses) {
		this.maskAddresses = maskAddresses;
	}

	public boolean isMaskOperands() {
		return maskOperands;
	}

	public void setMaskOperands(boolean maskOperands) {
		this.maskOperands = maskOperands;
	}

	public boolean isMaskScalars() {
		return maskScalars;
	}

	public void setMaskScalars(boolean maskScalars) {
		this.maskScalars = maskScalars;
	}
}
