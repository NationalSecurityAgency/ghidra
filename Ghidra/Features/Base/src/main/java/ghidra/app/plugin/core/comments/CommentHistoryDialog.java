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

import java.awt.BorderLayout;

import javax.swing.*;

import docking.DialogComponentProvider;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.listing.CodeUnit;
import ghidra.util.HelpLocation;

/**
 * Dialog to show comment history; has a tab for each comment type to show
 * history of changes to the comment.
 */
public class CommentHistoryDialog extends DialogComponentProvider {

	private JTabbedPane tabbedPane;
	private CommentHistoryPanel eolPanel;
	private CommentHistoryPanel prePanel;
	private CommentHistoryPanel postPanel;
	private CommentHistoryPanel platePanel;
	private CommentHistoryPanel repeatablePanel;

	CommentHistoryDialog(CodeUnit cu, int initialCommentType) {
		super("Show Comment History");
		setHelpLocation(new HelpLocation(HelpTopics.COMMENTS, "Show_Comment_History"));
		addWorkPanel(buildMainPanel(cu, initialCommentType));
		addDismissButton();
		setPreferredSize(500, 300);
	}

	private JPanel buildMainPanel(CodeUnit cu, int initialCommentType) {
		JPanel mainPanel = new JPanel(new BorderLayout());
		tabbedPane = new JTabbedPane();
		mainPanel.add(tabbedPane);
		// Note that we don't add a keylistener here as in some other tab panes. This is because
		// the tab components are not focusable so there is no need to try and process a "space" 
		// key. Instead, the history for each comment type is also added as a tooltip on its
		// corresponding tab. This will cause a screen reader to read the history for a tab
		// when it is selected.

		eolPanel = new CommentHistoryPanel(CodeUnit.EOL_COMMENT, cu);
		prePanel = new CommentHistoryPanel(CodeUnit.PRE_COMMENT, cu);
		postPanel = new CommentHistoryPanel(CodeUnit.POST_COMMENT, cu);
		platePanel = new CommentHistoryPanel(CodeUnit.PLATE_COMMENT, cu);
		repeatablePanel = new CommentHistoryPanel(CodeUnit.REPEATABLE_COMMENT, cu);

		addTab("  EOL Comment    ", eolPanel);
		addTab("  Pre Comment    ", prePanel);
		addTab("  Post Comment   ", postPanel);
		addTab("  Plate Comment  ", platePanel);
		addTab("  Repeatable Comment  ", repeatablePanel);

		return mainPanel;
	}

	private void addTab(String title, CommentHistoryPanel panel) {
		JScrollPane sp = new JScrollPane(panel);
		tabbedPane.addTab(title, null, sp, panel.getHistory());
	}
}
