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

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.model.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.task.SwingUpdateManager;
import resources.ResourceManager;

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
public class CommentWindowPlugin extends ProgramPlugin
		implements DomainObjectListener, OptionsChangeListener {

	private DockingAction selectAction;
	private CommentWindowProvider provider;
	private SwingUpdateManager reloadUpdateMgr;

	public CommentWindowPlugin(PluginTool tool) {
		super(tool, true, true);

		reloadUpdateMgr = new SwingUpdateManager(1000, 60000, new Runnable() {
			@Override
			public void run() {
				doReload();
			}
		});
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

	////////////////////////////////////////////////////////////////////////////
	//
	//  Implementation of DomainObjectListener
	//
	////////////////////////////////////////////////////////////////////////////

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

	// Junit access
	CommentWindowProvider getProvider() {
		return provider;
	}

	/**
	 * Create the action objects for this plugin.
	 */
	private void createActions() {

		selectAction = new DockingAction("Make Selection", getName(), false) {
			@Override
			public void actionPerformed(ActionContext context) {
				selectComment(provider.selectComment());
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof CommentWindowContext)) {
					return false;
				}
				CommentWindowContext commentWindowContext = (CommentWindowContext) context;
				GhidraTable table = commentWindowContext.getCommentTable();
				return table.getSelectedRows().length > 0;
			}
		};
		selectAction.setEnabled(false);
		ImageIcon icon = ResourceManager.loadImage("images/text_align_justify.png");
		selectAction.setPopupMenuData(new MenuData(new String[] { "Make Selection" }, icon));
		selectAction.setDescription("Selects currently selected comment in table");
		selectAction.setToolBarData(new ToolBarData(icon));

		installDummyAction(selectAction);

		tool.addLocalAction(provider, selectAction);

		DockingAction selectionAction = new SelectionNavigationAction(this, provider.getTable());
		tool.addLocalAction(provider, selectionAction);
	}

	private void installDummyAction(DockingAction action) {
		DummyKeyBindingsOptionsAction dummyAction =
			new DummyKeyBindingsOptionsAction(action.getName(), null);
		tool.addAction(dummyAction);

		ToolOptions options = tool.getOptions(ToolConstants.KEY_BINDINGS);
		options.addOptionsChangeListener(this);

		KeyStroke keyStroke = options.getKeyStroke(dummyAction.getFullName(), null);
		if (keyStroke != null) {
			action.setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.startsWith(selectAction.getName())) {
			KeyStroke keyStroke = (KeyStroke) newValue;
			selectAction.setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
	}

	void selectComment(ProgramSelection selection) {
		ProgramSelectionPluginEvent pspe =
			new ProgramSelectionPluginEvent("Selection", selection, currentProgram);
		firePluginEvent(pspe);
		processEvent(pspe);
	}

}
