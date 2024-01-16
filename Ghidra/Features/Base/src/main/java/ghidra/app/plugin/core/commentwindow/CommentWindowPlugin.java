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

import static ghidra.framework.model.DomainObjectEvent.*;
import static ghidra.program.util.ProgramEvent.*;

import docking.action.DockingAction;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.DomainObjectListenerBuilder;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.CommentChangeRecord;
import ghidra.program.util.ProgramSelection;
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
public class CommentWindowPlugin extends ProgramPlugin {

	private DockingAction selectAction;
	private CommentWindowProvider provider;
	private SwingUpdateManager reloadUpdateMgr;
	private DomainObjectListener domainObjectListener = createDomainObjectListener();

	public CommentWindowPlugin(PluginTool tool) {
		super(tool);

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
			currentProgram.removeListener(domainObjectListener);
		}
		provider.dispose();
		super.dispose();
	}

	private DomainObjectListener createDomainObjectListener() {
		// @formatter:off
		return new DomainObjectListenerBuilder(this)
			.any(RESTORED, CODE_REMOVED).terminate(this::reload)
			.with(CommentChangeRecord.class)
				.each(COMMENT_CHANGED).call(this::handleCommentChanged)
			.build();
		// @formatter:on
	}

	private void handleCommentChanged(CommentChangeRecord ccr) {
		int commentType = ccr.getCommentType();
		String oldComment = ccr.getOldComment();
		String newComment = ccr.getNewComment();
		Address commentAddress = ccr.getStart();

		// if old comment is null then the change is an add comment so add the comment to the table
		if (oldComment == null) {
			provider.commentAdded(commentAddress, commentType);
		}

		// if the new comment is null then the change is a delete comment so remove the comment from the table
		else if (newComment == null) {
			provider.commentRemoved(commentAddress, commentType);
		}
		// otherwise, the comment is changed so repaint the table
		else {
			provider.getComponent().repaint();
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
		program.addListener(domainObjectListener);
		provider.programOpened(program);
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(domainObjectListener);
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
