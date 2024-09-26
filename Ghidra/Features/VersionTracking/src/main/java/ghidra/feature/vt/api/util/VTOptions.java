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
package ghidra.feature.vt.api.util;

import org.jdom.Element;

import ghidra.framework.options.*;

public class VTOptions extends ToolOptions {

	private VTOptions(Element root) {
		super(root);
	}

	public VTOptions(String name) {
		super(name);
	}

	@Override
	public ToolOptions copy() {
		return new VTOptions(getXmlRoot(true));
	}

	/**
	 * A method that allows subclasses to tell the world where their options contain acceptable
	 * values
	 * @return true if valid
	 */
	public boolean validate() {
		return true;
	}

	@Override
	public String getDescription(String optionName) {
		Option option = getOption(optionName, OptionType.NO_TYPE, null);
		String description = option.getDescription();

		// Correlator factories may create an options object and set values without ever having 
		// registered the option.  Ideally we would update the VTOptions usage to make sure the 
		// options are all registered.  This check here is an easier fix.
		if (description.equals(Option.UNREGISTERED_OPTION)) {
			return option.getName();
		}
		return description;
	}
}
