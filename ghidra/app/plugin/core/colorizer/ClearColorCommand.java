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
package ghidra.app.plugin.core.colorizer;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;

class ClearColorCommand implements Command {

	private final AddressSetView set;
	private final ColorizingService colorizingService;

	ClearColorCommand(ColorizingService colorizingService) {
		this.colorizingService = colorizingService;
		this.set = null;
	}

	ClearColorCommand(ColorizingService colorizingService, AddressSetView set) {
		this.colorizingService = colorizingService;
		this.set = set;
	}

	@Override
	public boolean applyTo(DomainObject obj) {
		if (set != null && !set.isEmpty()) {
			colorizingService.clearBackgroundColor(set);
		}
		else {
			colorizingService.clearAllBackgroundColors();
		}
		return true;
	}

	@Override
	public String getStatusMsg() {
		return null;
	}

	@Override
	public String getName() {
		return "Clear Background Color";
	}

}
