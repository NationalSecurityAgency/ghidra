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
package ghidra.app.plugin.core.commentwindow;

import docking.action.DockingAction;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.SwingUpdateManager;

/*
 * This plugin shows a filterable Ghidra table containing all the comments in the active program
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Displays a list of comments",
	description = "This plugin provides a component for showing all the " +
			"comments in the current program.  The comment window can be filtered and used " +
			"for navigation.",
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class CommentWindowPlugin extends ProgramPlugin implements DomainObjectListener {

	private DockingAction selectAction;
	private CommentWindowProvider provider;
	private SwingUpdateManager reloadUpdateMgr;

	public CommentWindowPlugin(PluginTool tool) {
		super(tool, true, true);

		reloadUpdateMgr = new SwingUpdateManager(1000, 60000, () -> doReload());
	}

	@Override
	public void init() {
		super.init();

		provider = new CommentWindowProvider(this);
		createActions();
	}

	@Override
	public void dispose() {
		reloadUpdateMgr.dispose();
		if (currentProgram != null) {
			currentProgram.removeListener(this);
		}
		provider.dispose();
		super.dispose();
	}

	private int getCommentType(int type) {
		if (type == ChangeManager.DOCR_PRE_COMMENT_CHANGED) {
			return CodeUnit.PRE_COMMENT;
		}
		if (type == ChangeManager.DOCR_POST_COMMENT_CHANGED) {
			return CodeUnit.POST_COMMENT;
		}
		if (type == ChangeManager.DOCR_EOL_COMMENT_CHANGED) {
			return CodeUnit.EOL_COMMENT;
		}
		if (type == ChangeManager.DOCR_PLATE_COMMENT_CHANGED) {
			return CodeUnit.PLATE_COMMENT;
		}
		if ((type == ChangeManager.DOCR_REPEATABLE_COMMENT_CHANGED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_ADDED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_REMOVED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_CREATED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_DELETED)) {
			return CodeUnit.REPEATABLE_COMMENT;
		}
		return -1;
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {

		// reload the table if an undo/redo or clear code with options event happens (it isn't the
		// same as a delete comment)
		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED) ||
			ev.containsEvent(ChangeManager.DOCR_CODE_REMOVED)) {
			reload();
			return;
		}

		// check for and handle commend added, comment deleted, and comment changed events
		if (ev.containsEvent(ChangeManager.DOCR_PRE_COMMENT_CHANGED) ||
			ev.containsEvent(ChangeManager.DOCR_POST_COMMENT_CHANGED) ||
			ev.containsEvent(ChangeManager.DOCR_EOL_COMMENT_CHANGED) ||
			ev.containsEvent(ChangeManager.DOCR_PLATE_COMMENT_CHANGED) ||
			ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_CHANGED) ||
			ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_REMOVED) ||
			ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_CREATED) ||
			ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_DELETED)) {

			for (DomainObjectChangeRecord record : ev) {

				int type = record.getEventType();
				int commentType = getCommentType(type);
				if (commentType == -1) {
					continue;
				}

				ProgramChangeRecord pRec = (ProgramChangeRecord) record;

				String oldComment = (String) pRec.getOldValue();
				String newComment = (String) pRec.getNewValue();
				Address commentAddress = pRec.getStart();

				// if old comment is null then the change is an add comment so add the comment to the table
				if (oldComment == null) {
					provider.commentAdded(commentAddress, getCommentType(type));
				}

				// if the new comment is null then the change is a delete comment so remove the comment from the table
				else if (newComment == null) {
					provider.commentRemoved(commentAddress, getCommentType(type));
				}
				// otherwise, the comment is changed so repaint the table
				else {
					provider.getComponent().repaint();
				}
			}
		}
	}

	private void reload() {
		reloadUpdateMgr.update();
	}

	private void doReload() {
		provider.reload();
	}

	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
		provider.programOpened(program);
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
		provider.programClosed();
	}

	Program getProgram() {
		return currentProgram;
	}

	CommentWindowProvider getProvider() {
		return provider;
	}

	private void createActions() {

		selectAction = new MakeProgramSelectionAction(this, provider.getTable());
		tool.addLocalAction(provider, selectAction);

		DockingAction selectionAction = new SelectionNavigationAction(this, provider.getTable());
		tool.addLocalAction(provider, selectionAction);
	}

	private void selectComment(ProgramSelection selection) {
		ProgramSelectionPluginEvent pspe =
			new ProgramSelectionPluginEvent("Selection", selection, currentProgram);
		firePluginEvent(pspe);
		processEvent(pspe);
	}
}
