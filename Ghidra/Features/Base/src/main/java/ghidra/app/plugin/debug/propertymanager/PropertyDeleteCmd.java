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
package ghidra.app.plugin.debug.propertymanager;

import ghidra.framework.cmd.Command;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.PropertyMap;
import ghidra.program.model.util.PropertyMapManager;

/**
 * PropertyDeletedCmd
 */
class PropertyDeleteCmd implements Command<Program> {

	private String propName;
	private AddressSetView restrictedView;
	private String cmdName;

	/**
	 * Construct command for deleting program properties
	 * @param propName property name
	 * @param restrictedView set of address over which properties will be removed.
	 * If this is null or empty, all occurances of the property will be removed.
	 */
	public PropertyDeleteCmd(String propName, AddressSetView restrictedView) {
		this.propName = propName;
		this.restrictedView = restrictedView;
		this.cmdName = "Delete " + propName + " Properties";
	}

	@Override
	public String getName() {
		return cmdName;
	}

	@Override
	public boolean applyTo(Program program) {

		PropertyMapManager propMgr = program.getUsrPropertyManager();

		if (restrictedView != null && !restrictedView.isEmpty()) {
			PropertyMap<?> map = propMgr.getPropertyMap(propName);
			AddressRangeIterator ranges = restrictedView.getAddressRanges();
			while (ranges.hasNext()) {
				AddressRange range = ranges.next();
				map.removeRange(range.getMinAddress(), range.getMaxAddress());
			}
		}
		else {
			propMgr.removePropertyMap(propName);
		}
		return true;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return null;
	}

}
