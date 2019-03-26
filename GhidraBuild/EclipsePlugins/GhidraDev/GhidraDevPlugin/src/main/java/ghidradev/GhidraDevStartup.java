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
package ghidradev;

import org.eclipse.core.runtime.*;
import org.eclipse.core.runtime.jobs.Job;
import org.eclipse.swt.widgets.Display;
import org.eclipse.ui.*;
import org.eclipse.ui.intro.IIntroManager;
import org.eclipse.ui.intro.IIntroPart;

import ghidradev.ghidrascripteditor.ScriptEditorInitializer;
import ghidradev.ghidrasymbollookup.SymbolLookupInitializer;

/**
 * When Eclipse starts, initializes the plugin's subcomponents.
 */
public class GhidraDevStartup implements IStartup {

	@Override
	public void earlyStartup() {
		Job job = new Job(Activator.PLUGIN_ID + " startup") {
			@Override
			protected IStatus run(IProgressMonitor monitor) {
				monitor.beginTask("Initializing " + Activator.PLUGIN_ID, 2);

				// If we were launched from Ghidra, close the Eclipse welcome screen if present,
				// and make it so it never shows up again.
				if (Activator.getDefault().isLaunchedByGhidra()) {
					IIntroManager introManager = PlatformUI.getWorkbench().getIntroManager();
					IIntroPart intro = introManager.getIntro();
					if (intro != null) {
						Display.getDefault().syncExec(() -> introManager.closeIntro(intro));
					}
					PlatformUI.getPreferenceStore().setValue(
						IWorkbenchPreferenceConstants.SHOW_INTRO, false);
				}

				// Ask the user (only once) for consent before listening on any ports
				boolean firstTimeConsent = false;
				if (!GhidraRootPreferences.requestedConsentToOpenPorts()) {
					firstTimeConsent = EclipseMessageUtils.showQuestionDialog(
						Activator.PLUGIN_ID + "User Consent",
						Activator.PLUGIN_ID + " opens ports to enable communication with Ghidra " +
							"for various features such as initiating script editing and symbol " +
							"lookup from Ghidra.\n\nDo you consent to the ports being opened?\n\n" +
							"If you do not consent now, you can enable these features at any " +
							"time in the " + Activator.PLUGIN_ID + " preferences.");
					GhidraRootPreferences.setOpenPortConsentRequest(true);
				}

				// Initialize the script editor
				ScriptEditorInitializer.init(firstTimeConsent);
				monitor.worked(1);

				// Initialize symbol lookup
				SymbolLookupInitializer.init(firstTimeConsent);
				monitor.worked(1);

				monitor.done();
				return Status.OK_STATUS;
			}
		};
		job.schedule();
    }
}
