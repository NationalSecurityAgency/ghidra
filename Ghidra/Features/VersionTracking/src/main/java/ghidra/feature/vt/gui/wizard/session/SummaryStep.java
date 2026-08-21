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
package ghidra.feature.vt.gui.wizard.session;

import javax.swing.JComponent;

import docking.wizard.WizardModel;
import docking.wizard.WizardStep;
import ghidra.framework.model.DomainFile;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;

/**
 * Wizard step in the new version tracking session wizard for summarizing the information that
 * will be used to create a new session. 
 */
public class SummaryStep extends WizardStep<NewSessionData> {
	private SummaryPanel summaryPanel;

	protected SummaryStep(WizardModel<NewSessionData> model) {
		super(model, "Summary",
			new HelpLocation("VersionTrackingPlugin", "New_Session_Summary_Panel"));

		summaryPanel = new SummaryPanel();
	}

	@Override
	public void initialize(NewSessionData data) {
		StringBuilder label = new StringBuilder();
		StringBuilder summary = new StringBuilder();

		label.append("<html>");
		summary.append("<html>");

		// session mode

		label.append("Operation:");
		String opDescription = "New Version Tracking Session";
		summary.append(opDescription);
		label.append("<br>");
		summary.append("<br>");

		String sessionName = data.getSessionName();

		label.append("Session Name:");
		summary.append(sessionName);
		label.append("<br>");
		summary.append("<br>");

		String sourceProgramName = null;
		String destinationProgramName = null;

		DomainFile sourceProgram = data.getSourceFile();
		sourceProgramName = sourceProgram.getName();

		DomainFile destinationProgram = data.getDestinationFile();
		destinationProgramName = destinationProgram.getName();

		// source program

		label.append("Source Program:");
		summary.append(HTMLUtilities.escapeHTML(sourceProgramName));
		label.append("<br>");
		summary.append("<br>");

		// destination program

		label.append("Destination Program:");
		summary.append(HTMLUtilities.escapeHTML(destinationProgramName));
		label.append("<br>");
		summary.append("<br>");

		label.append("</html>");
		summary.append("</html>");

		summaryPanel.initialize(label.toString(), summary.toString());
	}

	@Override
	public boolean isValid() {
		return true;
	}

	@Override
	public boolean apply(NewSessionData data) {
		return true;
	}

	@Override
	public JComponent getComponent() {
		return summaryPanel;
	}

	@Override
	public boolean canFinish(NewSessionData data) {
		return true;
	}

	@Override
	public void populateData(NewSessionData data) {
		// this step is display only
	}

}
