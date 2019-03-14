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

import ghidra.framework.options.ToolOptions;

import org.jdom.Element;

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
	 */
	public boolean validate() {
		return true;
	}
}
