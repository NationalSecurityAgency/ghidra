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
package ghidra.app.plugin.core.comments;

import java.awt.event.KeyEvent;

import docking.action.*;
import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.comments.SetCommentsCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.cmd.Command;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;

/**
 * Class to handle end comments for a code unit in a program.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Add/edit comments",
	description = "Provides actions for adding, editing and removing all types of comments (EOL, POST, PRE, PLATE)."
)
//@formatter:on
public class CommentsPlugin extends Plugin implements OptionsChangeListener {

	// Delete Comments Action info
	private final static String[] DELETE_MENUPATH = new String[] { "Comments", "Delete" };

	private final static String[] HISTORY_MENUPATH = { "Comments", "Show History..." };

	private final static String OPTION_NAME = "Enter accepts comment";

	private DockingAction editAction;
	private DockingAction deleteAction;
	private DockingAction historyAction;
	private CommentsDialog dialog;
	private CommentHistoryDialog historyDialog;

	private DockingAction preCommentEditAction;
	private DockingAction postCommentEditAction;
	private DockingAction plateCommentEditAction;
	private DockingAction eolCommentEditAction;
	private DockingAction repeatableCommentEditAction;

	public CommentsPlugin(PluginTool tool) {
		super(tool);
		dialog = new CommentsDialog(this);

		// no events consumed

		createActions();
		initializeOptions(tool.getOptions("Comments"));
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		setOptions(options);
	}

	private void initializeOptions(ToolOptions options) {
		HelpLocation helpLocation = new HelpLocation(getName(), "Comments_Option");
		options.setOptionsHelpLocation(helpLocation);
		options.registerOption(OPTION_NAME, dialog.getEnterMode(), helpLocation,
			"Toggle for whether pressing the <Enter> key causes the comment to be entered," +
				" versus adding a new line character in the comment.");

		setOptions(options);
		options.addOptionsChangeListener(this);
	}

	private void setOptions(Options options) {
		dialog.setEnterMode(options.getBoolean(OPTION_NAME, dialog.getEnterMode()));
	}

	public void updateOptions() {
		Options options = tool.getOptions("Comments");

		options.setBoolean("Enter accepts comment", dialog.getEnterMode());
	}

	//////////////////////////////////////////////////////////////////////

	void updateComments(CodeUnit cu, String preComment, String postComment, String eolComment,
			String plateComment, String repeatableComment) {
		preComment = (preComment.length() == 0) ? null : preComment;
		postComment = (postComment.length() == 0) ? null : postComment;
		eolComment = (eolComment.length() == 0) ? null : eolComment;
		plateComment = (plateComment.length() == 0) ? null : plateComment;
		repeatableComment = (repeatableComment.length() == 0) ? null : repeatableComment;

		Command cmd = new SetCommentsCmd(cu.getMinAddress(), preComment, postComment, eolComment,
			plateComment, repeatableComment);

		tool.execute(cmd, cu.getProgram());
	}

	/**
	 * Called by the deleteAction to delete an end-of-line comment.
	 * @param program the {@link Program} for which to act
	 * @param loc the {@link ProgramLocation} for which to delete the comment
	 */
	void deleteComments(Program program, ProgramLocation loc) {
		int commentType = CommentType.getCommentType(null, loc, CodeUnit.EOL_COMMENT);
		Command cmd = new SetCommentCmd(loc.getByteAddress(), commentType, null);
		tool.execute(cmd, program);
	}

	private boolean hasComment(CodeUnit codeUnit, ProgramLocation loc) {
		if (codeUnit == null) {
			return false;
		}
		int commentType = CommentType.getCommentType(null, loc, CodeUnit.NO_COMMENT);
		return (commentType != CodeUnit.NO_COMMENT && codeUnit.getComment(commentType) != null);
	}

	////////////////////////////////////////////////////////////////
	// *** private methods ***
	////////////////////////////////////////////////////////////////
	private void createActions() {
		String pluginName = getName();

		editAction = CommentsActionFactory.getEditCommentsAction(dialog, name);
		tool.addAction(editAction);
		preCommentEditAction = CommentsActionFactory.getSetCommentsAction(dialog, name,
			"Set Pre Comment", CodeUnit.PRE_COMMENT);
		tool.addAction(preCommentEditAction);

		postCommentEditAction = CommentsActionFactory.getSetCommentsAction(dialog, name,
			"Set Post Comment", CodeUnit.POST_COMMENT);
		tool.addAction(postCommentEditAction);

		plateCommentEditAction = CommentsActionFactory.getSetCommentsAction(dialog, name,
			"Set Plate Comment", CodeUnit.PLATE_COMMENT);
		tool.addAction(plateCommentEditAction);

		eolCommentEditAction = CommentsActionFactory.getSetCommentsAction(dialog, name,
			"Set EOL Comment", CodeUnit.EOL_COMMENT);
		tool.addAction(eolCommentEditAction);

		repeatableCommentEditAction = CommentsActionFactory.getSetCommentsAction(dialog, name,
			"Set Repeatable Comment", CodeUnit.REPEATABLE_COMMENT);
		tool.addAction(repeatableCommentEditAction);

		deleteAction = new ListingContextAction("Delete Comments", pluginName) {
			@Override
			protected void actionPerformed(ListingActionContext context) {
				deleteComments(context.getProgram(), context.getLocation());
			}

			@Override
			public boolean isEnabledForContext(ListingActionContext context) {
				ProgramLocation loc = context.getLocation();
				if (!CommentsActionFactory.isCommentSupported(loc)) {
					return false;
				}
				if (loc instanceof CommentFieldLocation ||
					loc instanceof FunctionRepeatableCommentFieldLocation) {
					updatePopupPath(deleteAction, "Delete", loc);
					return hasComment(context.getCodeUnit(), loc);
				}
				getPopupMenuData().setMenuPath(new String[] { "Comments", "Delete" });
				return false;
			}
		};
		deleteAction.setPopupMenuData(new MenuData(DELETE_MENUPATH, null, "comments"));
		deleteAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));

		tool.addAction(deleteAction);

		historyAction = new ListingContextAction("Show Comment History", pluginName) {
			@Override
			protected void actionPerformed(ListingActionContext context) {
				showCommentHistory(context);
			}

			@Override
			public boolean isEnabledForContext(ListingActionContext context) {
				ProgramLocation loc = context.getLocation();
				if (!CommentsActionFactory.isCommentSupported(loc)) {
					return false;
				}
				if (loc instanceof CommentFieldLocation ||
					loc instanceof FunctionRepeatableCommentFieldLocation) {
					updatePopupPath(historyAction, "Show History for", loc);
				}
				else {
					historyAction.getPopupMenuData().setMenuPath(HISTORY_MENUPATH);
				}
				historyAction.setEnabled(CommentType.isCommentAllowed(context.getCodeUnit(), loc));
				return true;
			}
		};
		historyAction.setPopupMenuData(new MenuData(HISTORY_MENUPATH, null, "comments"));

		tool.addAction(historyAction);
	}

	private void showCommentHistory(ListingActionContext context) {
		CodeUnit cu = context.getCodeUnit();
		ProgramLocation loc = context.getLocation();
		if (historyDialog == null) {
			historyDialog = new CommentHistoryDialog();
		}
		historyDialog.showDialog(cu, CommentType.getCommentType(null, loc, CodeUnit.EOL_COMMENT),
			tool, context);
	}

	private void updatePopupPath(DockingAction action, String actionString, ProgramLocation loc) {

		String endString = "";
		if (action == historyAction) {
			endString = "...";
		}

		if (loc instanceof FunctionRepeatableCommentFieldLocation) {
			action.getPopupMenuData().setMenuPath(
				new String[] { "Comments", actionString + " Repeatable Comment" + endString });
			return;
		}

		if (loc instanceof PlateFieldLocation) {
			action.getPopupMenuData().setMenuPath(
				new String[] { "Comments", actionString + " Plate Comment" + endString });
			return;
		}

		CommentFieldLocation cfLoc = (CommentFieldLocation) loc;
		int type = cfLoc.getCommentType();
		switch (type) {
			case CodeUnit.PRE_COMMENT:
				action.getPopupMenuData().setMenuPath(
					new String[] { "Comments", actionString + " Pre-Comment" + endString });
				break;

			case CodeUnit.POST_COMMENT:
				action.getPopupMenuData().setMenuPath(
					new String[] { "Comments", actionString + " Post-Comment" + endString });
				break;

			case CodeUnit.EOL_COMMENT:
				action.getPopupMenuData().setMenuPath(
					new String[] { "Comments", actionString + " EOL Comment" + endString });
				break;

			case CodeUnit.REPEATABLE_COMMENT:
				action.getPopupMenuData().setMenuPath(
					new String[] { "Comments", actionString + " Repeatable Comment" + endString });
				break;
		}
	}
}
