/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.ActionContext;
import docking.DialogComponentProvider;

/**
 * Dialog to show comment history; has a tab for each comment type to show
 * history of changes to the comment.
 */
public class CommentHistoryDialog extends DialogComponentProvider implements ChangeListener {
	
	private Program program;
	private CodeUnit codeUnit;
		
	private JTabbedPane tabbedPane;
	private CommentHistoryPanel eolPanel;
	private CommentHistoryPanel prePanel;
	private CommentHistoryPanel postPanel;
	private CommentHistoryPanel platePanel;
	private CommentHistoryPanel repeatablePanel;
	
	private final static int[] COMMENT_INDEXES = 
		{CodeUnit.EOL_COMMENT,
		 CodeUnit.PRE_COMMENT,
		 CodeUnit.POST_COMMENT,
		 CodeUnit.PLATE_COMMENT,
		 CodeUnit.REPEATABLE_COMMENT}; 
		 
	/**
	 * Construct a new CommentHistoryDialog
	 * @param parent parent of this dialog
	 */
	CommentHistoryDialog() {
		super("Show Comment History");
		setHelpLocation(new HelpLocation(HelpTopics.COMMENTS, "Show_Comment_History")); 
		addWorkPanel(buildMainPanel());
		addDismissButton();
	}

	/* (non Javadoc)
	 * @see javax.swing.event.ChangeListener#stateChanged(javax.swing.event.ChangeEvent)
	 */
	public void stateChanged(ChangeEvent e) {
		int index = tabbedPane.getSelectedIndex();
		CommentHistoryPanel panel = getHistoryPanel(COMMENT_INDEXES[index]);
		panel.showCommentHistory(program, codeUnit.getMinAddress());
	}
	void showDialog(CodeUnit cu, int commentType, PluginTool tool, ActionContext context) {
		codeUnit = cu;
		program = cu.getProgram();
		CommentHistoryPanel panel = getHistoryPanel(commentType);
		panel.showCommentHistory(program, cu.getMinAddress());
		tabbedPane.removeChangeListener(this);
		
		for (int i=0;i<COMMENT_INDEXES.length; i++) {
			if (COMMENT_INDEXES[i] == commentType) {
				tabbedPane.setSelectedIndex(i);
				break;
			}
		}
		tabbedPane.addChangeListener(this);
        tool.showDialog( this, context.getComponentProvider() );
	}
	 
	private JPanel buildMainPanel() {
		JPanel mainPanel = new JPanel(new BorderLayout());
		tabbedPane = new JTabbedPane();
		mainPanel.add(tabbedPane);
		
		eolPanel = new CommentHistoryPanel(CodeUnit.EOL_COMMENT);
		prePanel = new CommentHistoryPanel(CodeUnit.PRE_COMMENT);
		postPanel = new CommentHistoryPanel(CodeUnit.POST_COMMENT);
		platePanel = new CommentHistoryPanel(CodeUnit.PLATE_COMMENT);
		repeatablePanel = new CommentHistoryPanel(CodeUnit.REPEATABLE_COMMENT);

		JScrollPane sp = new JScrollPane(eolPanel);
		JViewport vp = sp.getViewport();
		Dimension d = vp.getPreferredSize();
		sp.getViewport().setPreferredSize(new Dimension(500, d.height*7));
		tabbedPane.addTab("  EOL Comment    ",sp);
		tabbedPane.addTab("  Pre Comment    ",new JScrollPane(prePanel));
		tabbedPane.addTab("  Post Comment   ",new JScrollPane(postPanel));
		tabbedPane.addTab("  Plate Comment  ",new JScrollPane(platePanel));
		tabbedPane.addTab("  Repeatable Comment  ", new JScrollPane(repeatablePanel));
		
		tabbedPane.addChangeListener(this);
		return mainPanel;
	}
	
	private CommentHistoryPanel getHistoryPanel(int commentType) {
		switch(commentType) {
			case CodeUnit.EOL_COMMENT:
				return eolPanel;
			case CodeUnit.PRE_COMMENT:
				return prePanel;
			case CodeUnit.POST_COMMENT:
				return postPanel;
			case CodeUnit.PLATE_COMMENT:
				return platePanel;
			case CodeUnit.REPEATABLE_COMMENT:
				return repeatablePanel;
		}
		return null;	
	}
}
