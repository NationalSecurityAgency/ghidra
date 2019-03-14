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
package ghidra.feature.vt.gui.editors;

import static ghidra.feature.vt.gui.editors.TagEditorDialog.TagState.Action.*;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTMatchTag;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.editors.TagEditorDialog.TagState.Action;
import ghidra.framework.model.Transaction;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

import java.awt.BorderLayout;
import java.awt.event.*;
import java.util.*;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import docking.DialogComponentProvider;
import docking.widgets.OptionDialog;
import docking.widgets.list.ListRendererMouseEventForwarder;

public class TagEditorDialog extends DialogComponentProvider {

	private final VTSession session;
	private JList<TagState> list;
	private TagStateListModel listModel;

	public TagEditorDialog(VTSession session) {
		super("Tag Editor", true, true, true, false);
		this.session = session;

		addWorkPanel(buildWorkPanel());

		addOKButton();
		addCancelButton();

		setPreferredSize(200, 400);
	}

	private JComponent buildWorkPanel() {
		JPanel mainPanel = new JPanel(new BorderLayout());

		JScrollPane scrollPane = new JScrollPane();
		listModel = new TagStateListModel(getTags());
		list = new JList<>(listModel);
		list.setBackground(scrollPane.getBackground());
		list.setCellRenderer(new TagEditorRenderer(list, listModel));
		list.getSelectionModel().setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

		MouseAdapter mouseAdapter = new ListRendererMouseEventForwarder();

		list.addMouseMotionListener(mouseAdapter);
		list.addMouseListener(mouseAdapter);

		scrollPane.setViewportView(list);
		mainPanel.add(scrollPane, BorderLayout.CENTER);

		JButton addButton = new JButton("Add");
		addButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				TagState newState = createNewTag();
				if (newState == null) {
					return;
				}
				listModel.addElement(newState);
				list.repaint();
			}

			private TagState createNewTag() {
				String tagName =
					OptionDialog.showInputSingleLineDialog(getComponent(), "Create Tag",
						"Enter tag name: ", "");
				if (tagName == null || "".equals(tagName.trim())) {
					return null;
				}
				return new TagState(tagName, new VTMatchTagImpl(tagName), ADD);
			}
		});

		final JButton deleteButton = new JButton("Delete");
		deleteButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				List<TagState> selectedValues = list.getSelectedValuesList();
				for (TagState state : selectedValues) {
					Action action = state.getAction();
					if (action == UNMODIFIED) {
						// mark for deletion, but don't actually delete yet
						state.setAction(DELETE);
					}
					else if (action == ADD) {
						// just remove tags added by the user
						listModel.removeElement(state);
					}
				}
				list.repaint();
			}
		});
		deleteButton.setEnabled(false);

		list.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				if (e.getValueIsAdjusting()) {
					return;
				}

				int[] selectedIndices = list.getSelectedIndices();
				if (selectedIndices == null || selectedIndices.length == 0) {
					deleteButton.setEnabled(false);
				}
				else {
					deleteButton.setEnabled(true);
				}
			}
		});

		JPanel editPanel = new JPanel();
		editPanel.add(addButton);
		editPanel.add(Box.createHorizontalStrut(5));
		editPanel.add(deleteButton);

		mainPanel.add(editPanel, BorderLayout.SOUTH);

		return mainPanel;
	}

	private Set<VTMatchTag> getTags() {
		return session.getMatchTags();
	}

	@Override
	protected void okCallback() {
		int size = listModel.getSize();
		Set<TagState> tags = new HashSet<TagState>(size);
		for (int i = 0; i < size; i++) {
			tags.add(listModel.getElementAt(i));
		}

		CommitTagEditsTask task = new CommitTagEditsTask(session, tags);
		new TaskLauncher(task, getComponent());
		close();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	class TagStateListModel extends AbstractListModel<TagState> {

		private List<TagState> data = new ArrayList<TagState>();

		TagStateListModel(Set<VTMatchTag> tags) {
			for (VTMatchTag tag : tags) {
				addElement(new TagState(tag.getName(), tag, UNMODIFIED));
			}
		}

		void addElement(TagState state) {
			data.add(state);
			Collections.sort(data);
			fireContentsChanged(this, 0, getSize());
		}

		void removeElement(TagState state) {
			int index = data.indexOf(state);
			data.remove(state);
			fireIntervalRemoved(state, index, index);
		}

		@Override
		public TagState getElementAt(int index) {
			return data.get(index);
		}

		@Override
		public int getSize() {
			return data.size();
		}
	}

	static class TagState implements Comparable<TagState> {

		enum Action {
			UNMODIFIED, ADD, DELETE
		}

		private VTMatchTag tag;
		private final String tagName;
		private Action action;
		private boolean mousePressed;

		TagState(String tagName, VTMatchTag tag, Action action) {
			this.tagName = tagName;
			this.tag = tag;
			this.action = action;
		}

		Action getAction() {
			return action;
		}

		boolean isUnmodified() {
			return action == UNMODIFIED;
		}

		void setAction(Action action) {
			this.action = action;
		}

		String getTagName() {
			return tagName;
		}

		VTMatchTag getTag() {
			return tag;
		}

		void setMousePressed(boolean pressed) {
			mousePressed = pressed;
		}

		boolean isMousePressed() {
			return mousePressed;
		}

		@Override
		public int compareTo(TagState o) {
			if (tagName == null) {
				return o.tagName == null ? 0 : 1;
			}
			else if (o.tagName == null) {
				return -1;
			}

			return tagName.compareToIgnoreCase(o.tagName);
		}

		@Override
		public String toString() {
			return getClass().getSimpleName() + "[" + tagName + ", " + action + "]";
		}

		public void restoreState() {
			if (tag instanceof VTMatchTagImpl) {
				// we are not yet created, so our state should go back to ADD
				action = ADD;
			}
			else {
				// we exist, so our default state is unmodified
				action = UNMODIFIED;
			}
		}
	}

	private class CommitTagEditsTask extends Task {

		private final Set<TagState> tags;

		public CommitTagEditsTask(VTSession session, Set<TagState> tags) {
			super("Commiting Tag Edits", true, true, true);
			this.tags = tags;
		}

		@Override
		public void run(TaskMonitor monitor) {
			boolean commit = true;
			VTSessionDB sessionDB = (VTSessionDB) session;
			Program program = sessionDB.getDestinationProgram();

			if (hasTransactionsOpen(sessionDB)) {
				return;
			}

			int programTransactionID = program.startTransaction(getTaskTitle());
			int matchSetTransactionID = sessionDB.startTransaction(getTaskTitle());
			try {
				doWork(monitor);
			}
			catch (CancelledException e) {
				commit = false;
			}
			catch (Exception e) {
				commit = false;
				Msg.showError(this, null, "Unable to Set Match Tag",
					"An unexpected error occurred attempting to set match tag.", e);
			}
			finally {
				try {
					program.endTransaction(programTransactionID, commit);
				}
				catch (Exception e) {
					// don't care
				}
				finally {
					sessionDB.endTransaction(matchSetTransactionID, commit);
				}
			}
		}

		private void doWork(TaskMonitor monitor) throws CancelledException {
			monitor.initialize(tags.size());

			for (TagState tagState : tags) {
				monitor.checkCanceled();
				switch (tagState.action) {
					case ADD:
						addTag(tagState.getTagName());
						break;
					case DELETE:
						deleteTag(tagState.getTag());
						break;
					case UNMODIFIED:
						// nothing to do
				}

				monitor.incrementProgress(1);
			}
		}

		private void deleteTag(VTMatchTag tag) {
			session.deleteMatchTag(tag);
		}

		private void addTag(String tagName) {
			session.createMatchTag(tagName);
		}

		private boolean hasTransactionsOpen(VTSessionDB sessionDB) {
			Program program = sessionDB.getDestinationProgram();
			Transaction transaction = program.getCurrentTransaction();
			if (transaction != null) {
				Msg.showWarn(this, null, "Unable to Set Match Tag",
					"The program \"" + program.getName() + "\"already has a transaction open: " +
						transaction.getDescription());
				return true;
			}

			Transaction matchSetTransaction = sessionDB.getCurrentTransaction();
			if (matchSetTransaction != null) {
				Msg.showWarn(this, null, "Unable to Set Match Tag",
					"Transaction already open for the Match Set Manager ");
				return true;
			}
			return false;
		}

	}

	private class VTMatchTagImpl implements VTMatchTag {

		private final String name;

		VTMatchTagImpl(String name) {
			this.name = name;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public int compareTo(VTMatchTag o) {
			return getName().compareTo(o.getName());
		}
	}
}
