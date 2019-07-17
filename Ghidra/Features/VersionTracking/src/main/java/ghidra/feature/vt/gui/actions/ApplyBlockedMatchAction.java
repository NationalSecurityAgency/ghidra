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
package ghidra.feature.vt.gui.actions;

import java.util.*;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchContext;
import ghidra.feature.vt.gui.task.ApplyBlockedMatchTask;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import resources.Icons;

/**
 * The ApplyBlockedMatchAction allows the user to apply a match that is currently blocked.
 * It clears any conflicting matches that are currently accepted in order to apply the desired match.
 * The user is prompted to verify the conflicting matches should be cleared before proceeding.
 */
public class ApplyBlockedMatchAction extends DockingAction {

	public static String NAME = "Apply Blocked Match";
	private static final String MENU_GROUP = VTPlugin.EDIT_MENU_GROUP;

	private final VTController controller;

	public ApplyBlockedMatchAction(VTController controller) {
		super(NAME, VTPlugin.OWNER);
		this.controller = controller;

		setPopupMenuData(new MenuData(new String[] { "Apply Blocked Match" },
			Icons.APPLY_BLOCKED_MATCH_ICON, MENU_GROUP));
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Apply_Blocked_Match"));

	}

	@Override
	public void actionPerformed(ActionContext context) {
		VTMatchContext matchContext = (VTMatchContext) context;
		List<VTMatch> matches = matchContext.getSelectedMatches();
		if (matches.size() != 1) {
			return;
		}
		VTMatch match = matches.get(0);
		VTAssociation association = match.getAssociation();
		VTAssociationStatus status = association.getStatus();
		if (status != VTAssociationStatus.BLOCKED) {
			return;
		}
		List<VTAssociation> conflicts = getConflictingMatches(match);
		String conflictMessage = getConflictingMatchesDisplayString(match, conflicts);
		int response = OptionDialog.showOptionDialog(null, "Clear Conflicting Matches and Apply?",
			conflictMessage, "Clear and Apply", OptionDialog.QUESTION_MESSAGE);
		if (response == OptionDialog.OPTION_ONE) {
			ApplyBlockedMatchTask task = new ApplyBlockedMatchTask(controller, match, conflicts);
			controller.runVTTask(task);
		}

	}

	private List<VTAssociation> getConflictingMatches(VTMatch match) {
		ArrayList<VTAssociation> list = new ArrayList<>();
		VTAssociation association = match.getAssociation();
		Collection<VTAssociation> relatedAssociations = association.getRelatedAssociations();
		for (VTAssociation relatedAssociation : relatedAssociations) {
			if (relatedAssociation.getStatus() == VTAssociationStatus.ACCEPTED) {
				list.add(relatedAssociation);
			}
		}
		return list;
	}

	private String getConflictingMatchesDisplayString(VTMatch match,
			List<VTAssociation> conflicts) {
		StringBuilder buffer = new StringBuilder();
		buffer.append("<html>");
		int count = 0;
		for (VTAssociation conflictingAssociation : conflicts) {
			if (conflictingAssociation.getStatus() == VTAssociationStatus.ACCEPTED) {
				buffer.append("    Conflicting ");
				buffer.append(getAssociationDisplayString(conflictingAssociation));
				buffer.append(".<br>");
				count++;
			}
		}
		buffer.append(" <br>");
		buffer.append("Do you want to clear the conflicting accepted match");
		if (count > 1) {
			buffer.append("es");
		}
		buffer.append(" and all ");
		buffer.append((count > 1) ? "their" : "its");
		buffer.append(" applied markup items<br>");
		buffer.append("and then apply the ");
		buffer.append(getAssociationDisplayString(match.getAssociation()));
		buffer.append(".");
		buffer.append("</html>");
		return buffer.toString();
	}

	private String getAssociationDisplayString(VTAssociation association) {
		return association.getType().toString() + " match with source of <b>" +
			HTMLUtilities.escapeHTML(association.getSourceAddress().toString()) +
			"</b> and destination of <b>" +
			HTMLUtilities.escapeHTML(association.getDestinationAddress().toString()) + "</b>";
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof VTMatchContext)) {
			return false;
		}
		VTMatchContext matchContext = (VTMatchContext) context;
		List<VTMatch> matches = matchContext.getSelectedMatches();
		if (matches.size() != 1) {
			return false;
		}

		VTMatch match = matches.get(0);
		VTAssociation association = match.getAssociation();
		VTAssociationStatus status = association.getStatus();
		return status == VTAssociationStatus.BLOCKED;

	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}
}
