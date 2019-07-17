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
package help.screenshot;

import org.junit.Test;

import ghidra.app.plugin.core.console.ConsoleComponentProvider;
import ghidra.app.services.ConsoleService;

public class ConsolePluginScreenShots extends GhidraScreenShotGenerator {

	public ConsolePluginScreenShots() {
		super();
	}

	@Override
	public void loadProgram() {
		// don't load a program
	}

	@Test
	public void testConsole() {
		showProvider(ConsoleComponentProvider.class);
		ConsoleService service = tool.getService(ConsoleService.class);
		service.addMessage("Sample", "This is a sample console message.");
		service.addMessage("MyScript", "This is a sample script output.\n\n");
		service.addErrorMessage("Sample", "This is an error message.");

		captureIsolatedProvider(ConsoleComponentProvider.class, 600, 300);

	}
}
