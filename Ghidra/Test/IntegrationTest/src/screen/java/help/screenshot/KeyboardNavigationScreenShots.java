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

import docking.actions.dialog.ActionChooserDialog;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;

public class KeyboardNavigationScreenShots extends GhidraScreenShotGenerator {
	@Test
	public void testActionsDialog() {

		CodeViewerProvider provider = getProvider(CodeViewerProvider.class);
		ActionChooserDialog dialog = getSwing(() -> {
			ActionChooserDialog actionsDialog =
				new ActionChooserDialog(tool, provider, provider.getActionContext(null));
			actionsDialog.setPreferredSize(600, 400);
			return actionsDialog;
		});
		runSwing(() -> tool.showDialog(dialog), false);

		captureDialog();
		close(dialog);
	}
}
