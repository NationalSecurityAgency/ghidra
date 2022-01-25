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
package ghidra.app.plugin.core.assembler;

import org.junit.Test;

import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import help.screenshot.GhidraScreenShotGenerator;

public class AssemblerPluginScreenShots extends GhidraScreenShotGenerator {
	@Test
	public void testCaptureAssembler() throws Exception {
		setToolSize(1000, 800);

		positionListingTop(0x00405120);
		positionCursor(0x0040512e);
		AssemblerPlugin assemblerPlugin = addPlugin(tool, AssemblerPlugin.class);
		CodeViewerProvider codeViewer = waitForComponentProvider(CodeViewerProvider.class);

		performAction(assemblerPlugin.patchInstructionAction, codeViewer, true);

		AssemblyDualTextField input = assemblerPlugin.patchInstructionAction.input;
		runSwing(() -> {
			input.auto.startCompletion(input.getOperandsField());
			input.auto.flushUpdates();
			input.auto.select(0);
		});

		captureProviderWithScreenShot(codeViewer);
	}
}
