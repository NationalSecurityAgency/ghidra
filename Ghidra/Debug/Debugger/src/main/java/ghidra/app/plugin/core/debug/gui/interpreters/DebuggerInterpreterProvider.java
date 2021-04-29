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
package ghidra.app.plugin.core.debug.gui.interpreters;

import ghidra.app.plugin.core.interpreter.*;

public class DebuggerInterpreterProvider extends InterpreterComponentProvider {

	// If only ComponentProvider#subTitle weren't private
	// Really, if only InterpreterComponentProvider#getSubTitle weren't overridden
	// TODO: Have it just call setSubTitle in its constructor
	protected String subTitle;

	public DebuggerInterpreterProvider(InterpreterPanelPlugin plugin,
			InterpreterConnection interpreter, boolean visible) {
		super(plugin, interpreter, visible);
	}

	@Override
	public void setSubTitle(String subTitle) {
		this.subTitle = subTitle;
		super.setSubTitle(subTitle);
	}

	@Override
	public String getSubTitle() {
		return subTitle;
	}
}
