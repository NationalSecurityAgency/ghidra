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
package ghidra.framework.plugintool;

import ghidra.framework.plugintool.util.PluginClassManager;

/**
 * A dummy version of {@link PluginTool} that tests can use when they need an instance of 
 * the PluginTool, but do not wish to use a real version
 */
public class DummyPluginTool extends PluginTool {

	public DummyPluginTool() {
		super(null /*project*/, null /*project manager*/, new DummyToolServices(), "Dummy Tool",
			true, true, false);
	}

	@Override
	public PluginClassManager getPluginClassManager() {
		return null;
	}

	private static class DummyToolServices extends ToolServicesAdapter {

		@Override
		public void closeTool(PluginTool t) {
			// If we call this, then the entire test VM will exit, which is bad
			// System.exit(0);
		}
	}
}
