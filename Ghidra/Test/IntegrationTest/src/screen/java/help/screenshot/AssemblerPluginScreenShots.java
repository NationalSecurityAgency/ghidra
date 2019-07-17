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

import java.awt.AWTException;
import java.awt.Robot;
import java.awt.event.KeyEvent;

import org.junit.Test;

import docking.action.DockingActionIf;
import ghidra.app.plugin.core.assembler.AssemblerPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.framework.plugintool.util.PluginException;

public class AssemblerPluginScreenShots extends GhidraScreenShotGenerator {
	@Test
	public void testCaptureAssembler() throws PluginException, AWTException, InterruptedException {
		setToolSize(1000, 800);

		positionListingTop(0x00405120);
		positionCursor(0x0040512e);
		tool.addPlugin(AssemblerPlugin.class.getName());

		DockingActionIf action = getAction(tool, "AssemblerPlugin", "Assemble");

		performAction(action, true);

		Robot rob = new Robot();
		rob.keyPress(KeyEvent.VK_RIGHT);
		rob.keyRelease(KeyEvent.VK_RIGHT);

		// TODO: Will this work on Mac? control vs command
		rob.keyPress(KeyEvent.VK_CONTROL);
		rob.keyPress(KeyEvent.VK_SPACE);
		rob.keyRelease(KeyEvent.VK_SPACE);
		rob.keyRelease(KeyEvent.VK_CONTROL);

		Thread.sleep(100);

		rob.keyPress(KeyEvent.VK_ESCAPE);
		rob.keyRelease(KeyEvent.VK_ESCAPE);

		Thread.sleep(100);

		rob.keyPress(KeyEvent.VK_CONTROL);
		rob.keyPress(KeyEvent.VK_SPACE);
		rob.keyRelease(KeyEvent.VK_SPACE);
		rob.keyRelease(KeyEvent.VK_CONTROL);

		captureProvider(CodeViewerProvider.class);
	}
}
