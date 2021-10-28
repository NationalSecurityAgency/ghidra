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
import java.awt.event.*;
import java.util.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.Document;
import javax.swing.text.JTextComponent;

import docking.*;
import docking.widgets.OptionDialog;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import ghidra.app.util.viewer.field.AnnotatedStringHandler;
import ghidra.app.util.viewer.field.Annotation;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.CodeUnit;
import ghidra.util.HelpLocation;

/**
 * Dialog for setting the comments for a CodeUnit.
 */
public class CommentsDialog extends DialogComponentProvider implements KeyListener {

	private JTextArea eolField;
	private JTextArea preField;
	private JTextArea postField;
	private JTextArea plateField;
	private JTextArea repeatableField;

	private Map<Document, UndoRedoKeeper> documentUndoRedoMap = new HashMap<>(9);

	private String preComment;
	private String postComment;
	private String eolComment;
	private String plateComment;
	private String repeatableComment;

	private JTabbedPane tab;

	private CommentsPlugin plugin;
	private CodeUnit codeUnit;

	private boolean wasChanged;

	private boolean enterMode = false;
	private JCheckBox enterBox = new GCheckBox("Enter accepts comment", enterMode);
	{
		enterBox.addChangeListener(e -> {
			enterMode = enterBox.isSelected();
			plugin.updateOptions();
		});
	}
	private JPopupMenu popup = new JPopupMenu();

	CommentsDialog(CommentsPlugin plugin) {
		super("Set Comments");
		setHelpLocation(new HelpLocation(plugin.getName(), "Comments"));
		addWorkPanel(createPanel());

		addOKButton();
		addApplyButton();
		addDismissButton();
		this.plugin = plugin;
	}

	/**
	 * Display this dialog.
	 * @param cu code unit
	 * @param type comment type
	 */
	void showDialog(CodeUnit cu, int type) {
		setTitle("Set Comment(s) at Address " + cu.getMinAddress());
		codeUnit = cu;

		preComment = cu.getComment(CodeUnit.PRE_COMMENT);
		postComment = cu.getComment(CodeUnit.POST_COMMENT);
		eolComment = cu.getComment(CodeUnit.EOL_COMMENT);
		plateComment = cu.getComment(CodeUnit.PLATE_COMMENT);
		repeatableComment = cu.getComment(CodeUnit.REPEATABLE_COMMENT);

		preComment = (preComment == null) ? "" : preComment;
		postComment = (postComment == null) ? "" : postComment;
		eolComment = (eolComment == null) ? "" : eolComment;
		plateComment = (plateComment == null) ? "" : plateComment;
		repeatableComment = (repeatableComment == null) ? "" : repeatableComment;

		if (!preField.getText().equals(preComment)) {
			preField.setText(preComment);
		}

		if (!postField.getText().equals(postComment)) {
			postField.setText(postComment);
		}

		if (!eolField.getText().equals(eolComment)) {
			eolField.setText(eolComment);
		}

		if (!plateField.getText().equals(plateComment)) {
			plateField.setText(plateComment);
		}

		if (!repeatableField.getText().equals(repeatableComment)) {
			repeatableField.setText(repeatableComment);
		}

		setCommentType(type);

		setApplyEnabled(false);
		setFocusComponent(getSelectedTextArea());
		PluginTool tool = plugin.getTool();
		tool.showDialog(this);
	}

	void setCommentType(int type) {
		switch (type) {
			case CodeUnit.EOL_COMMENT:
				tab.setSelectedIndex(0);
				break;
			case CodeUnit.PRE_COMMENT:
				tab.setSelectedIndex(1);
				break;
			case CodeUnit.POST_COMMENT:
				tab.setSelectedIndex(2);
				break;
			case CodeUnit.PLATE_COMMENT:
				tab.setSelectedIndex(3);
				break;
			case CodeUnit.REPEATABLE_COMMENT:
				tab.setSelectedIndex(4);
				break;
		}
	}

	/////////////////////////////////////////////
	// *** GhidraDialog "callback" methods ***
	/////////////////////////////////////////////

	/**
	 * Callback for the cancel button.
	 */
	@Override
	protected void cancelCallback() {

		if (wasChanged) {
			int result = OptionDialog.showYesNoCancelDialog(getComponent(), "Save Changes?",
				"Some comments were modified.\nSave Changes?");
			if (result == OptionDialog.OPTION_ONE) {
				applyCallback();
			}
			else if (result == OptionDialog.OPTION_TWO) {
				if (!preField.getText().equals(preComment)) {
					preField.setText(preComment);
				}

				if (!postField.getText().equals(postComment)) {
					postField.setText(postComment);
				}

				if (!eolField.getText().equals(eolComment)) {
					eolField.setText(eolComment);
				}

				if (!plateField.getText().equals(plateComment)) {
					plateField.setText(plateComment);
				}

				if (!repeatableField.getText().equals(repeatableComment)) {
					repeatableField.setText(repeatableComment);
				}
				wasChanged = false;
				setApplyEnabled(false);
			}
			else { // cancel cancel
				return;
			}
		}

		close();
	}

	/**
	 * Callback for the OK button.
	 */
	@Override
	protected void okCallback() {
		if (wasChanged) {
			applyCallback();
		}
		close();
		clearState();
	}

	private void clearState() {
		Collection<UndoRedoKeeper> undoRedoKeepers = documentUndoRedoMap.values();
		for (UndoRedoKeeper undoRedoKeeper : undoRedoKeepers) {
			undoRedoKeeper.clear();
		}
	}

	/**
	 * Callback for the Apply button.
	 */
	@Override
	protected void applyCallback() {
		preComment = preField.getText();
		postComment = postField.getText();
		eolComment = eolField.getText();
		plateComment = plateField.getText();
		repeatableComment = repeatableField.getText();

		plugin.updateComments(codeUnit, preComment, postComment, eolComment, plateComment,
			repeatableComment);

		wasChanged = false;
		setApplyEnabled(false);
	}

	////////////////////////////////////////////////////////////////////
	// ** private methods **
	////////////////////////////////////////////////////////////////////

	private AnnotationAdapterWrapper[] getAnnotationAdapterWrappers() {
		AnnotatedStringHandler[] annotations = Annotation.getAnnotatedStringHandlers();
		AnnotationAdapterWrapper[] retVal = new AnnotationAdapterWrapper[annotations.length];
		for (int i = 0; i < annotations.length; i++) {
			retVal[i] = new AnnotationAdapterWrapper(annotations[i]);
		}
		return retVal;
	}

	/**
	 * Create the panel for the dialog.
	 */
	private JPanel createPanel() {

		JPanel panel = new JPanel(new BorderLayout());
		tab = new JTabbedPane();
		panel.add(tab, BorderLayout.CENTER);

		JPanel auxiliaryControlPanel = new JPanel(new BorderLayout());
		auxiliaryControlPanel.add(enterBox, BorderLayout.SOUTH);

		AnnotationAdapterWrapper[] annotations = getAnnotationAdapterWrappers();
		Arrays.sort(annotations);
		GComboBox<AnnotationAdapterWrapper> annotationsComboBox = new GComboBox<>(annotations);
		JButton addAnnotationButton = new JButton("Add Annotation");
		addAnnotationButton.addActionListener(e -> {
			JTextArea currentTextArea = getSelectedTextArea();
			AnnotationAdapterWrapper aaw =
				(AnnotationAdapterWrapper) annotationsComboBox.getSelectedItem();
			currentTextArea.insert(aaw.getPrototypeString(),
				currentTextArea.getCaretPosition());
			currentTextArea.setCaretPosition(currentTextArea.getCaretPosition() - 1);
		});
		JPanel annoPanel = new JPanel();
		annoPanel.add(addAnnotationButton);
		annoPanel.add(annotationsComboBox);
		auxiliaryControlPanel.add(annoPanel, BorderLayout.NORTH);

		panel.add(auxiliaryControlPanel, BorderLayout.SOUTH);

		preField = new JTextArea(5, 80) {
			@Override
			public boolean getScrollableTracksViewportWidth() {
				boolean b = super.getScrollableTracksViewportWidth();
				return b;
			}
		};
		postField = new JTextArea(5, 80);
		plateField = new JTextArea(5, 80);
		eolField = new JTextArea(5, 80);
		repeatableField = new JTextArea(5, 80);

		DocumentListener dl = new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				checkChanged();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				checkChanged();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				checkChanged();
			}
		};

		Document document = preField.getDocument();
		document.addDocumentListener(dl);
		installUndoRedo(preField);

		document = postField.getDocument();
		document.addDocumentListener(dl);
		installUndoRedo(postField);

		document = eolField.getDocument();
		document.addDocumentListener(dl);
		installUndoRedo(eolField);

		document = plateField.getDocument();
		document.addDocumentListener(dl);
		installUndoRedo(plateField);

		document = repeatableField.getDocument();
		document.addDocumentListener(dl);
		installUndoRedo(repeatableField);

		preField.addKeyListener(this);
		postField.addKeyListener(this);
		eolField.addKeyListener(this);
		plateField.addKeyListener(this);
		repeatableField.addKeyListener(this);

		preField.setLineWrap(true);
		postField.setLineWrap(true);
		eolField.setLineWrap(true);
		plateField.setLineWrap(true);
		repeatableField.setLineWrap(true);

		preField.setWrapStyleWord(true);
		postField.setWrapStyleWord(true);
		eolField.setWrapStyleWord(true);
		plateField.setWrapStyleWord(true);
		repeatableField.setWrapStyleWord(true);

		tab.addTab("  EOL Comment    ", new JScrollPane(eolField));
		tab.addTab("  Pre Comment    ", new JScrollPane(preField));
		tab.addTab("  Post Comment   ", new JScrollPane(postField));
		tab.addTab("  Plate Comment  ", new JScrollPane(plateField));
		tab.addTab("  Repeatable Comment  ", new JScrollPane(repeatableField));

		tab.addChangeListener(ev -> chooseFocus());

		ActionListener addAnnotationAction = e -> {
			JTextArea currentTextArea = getSelectedTextArea();
			for (AnnotationAdapterWrapper annotation : annotations) {
				if (annotation.toString().equals(e.getActionCommand())) {
					currentTextArea.insert(annotation.getPrototypeString(),
						currentTextArea.getCaretPosition());
					currentTextArea.setCaretPosition(currentTextArea.getCaretPosition() - 1);
				}
			}
		};

		JMenu insertMenu = new JMenu("Insert");
		for (AnnotationAdapterWrapper annotation : annotations) {
			JMenuItem menuItem = new JMenuItem(annotation.toString());
			menuItem.addActionListener(addAnnotationAction);
			insertMenu.add(menuItem);
		}
		popup.add(insertMenu);

		preField.addMouseListener(new PopupListener());
		postField.addMouseListener(new PopupListener());
		eolField.addMouseListener(new PopupListener());
		plateField.addMouseListener(new PopupListener());
		repeatableField.addMouseListener(new PopupListener());

		return panel;
	}

	private void installUndoRedo(JTextComponent textComponent) {
		UndoRedoKeeper undoRedoKeeper = DockingUtils.installUndoRedo(textComponent);

		// save for later so that we can clear when the dialog is closed
		Document document = textComponent.getDocument();
		documentUndoRedoMap.put(document, undoRedoKeeper);
	}

	private void checkChanged() {
		if (hasChanges()) {
			wasChanged = true;
			setApplyEnabled(true);
		}
		else {
			wasChanged = false;
			setApplyEnabled(false);
		}
	}

	private boolean hasChanges() {
		if (!preComment.equals(preField.getText())) {
			return true;
		}
		if (!postComment.equals(postField.getText())) {
			return true;
		}
		if (!eolComment.equals(eolField.getText())) {
			return true;
		}
		if (!plateComment.equals(plateField.getText())) {
			return true;
		}
		if (!repeatableComment.equals(repeatableField.getText())) {
			return true;
		}
		return false;
	}

	private JTextArea getSelectedTextArea() {
		int index = tab.getSelectedIndex();
		switch (index) {
			case 0:
				return eolField;
			case 1:
				return preField;
			case 2:
				return postField;
			case 3:
				return plateField;
			case 4:
				return repeatableField;
			default:
				return null;
		}
	}

	private void chooseFocus() {
		getSelectedTextArea().requestFocus();
	}

	@Override
	public void keyTyped(KeyEvent e) {
		// don't care--keyPressed() only
	}

	@Override
	public void keyPressed(KeyEvent e) {
		JTextArea textArea = (JTextArea) e.getSource();
		if (e.getKeyCode() != KeyEvent.VK_ENTER) {
			return;
		}

		int modifiers = e.getModifiersEx();
		if ((modifiers & InputEvent.SHIFT_DOWN_MASK) == InputEvent.SHIFT_DOWN_MASK) {
			textArea.replaceSelection("\n");
			e.consume();
			return;
		}

		if ((modifiers & InputEvent.CTRL_DOWN_MASK) == InputEvent.CTRL_DOWN_MASK) {
			okCallback(); // Control-Enter allows closes the dialog
			e.consume();
			return;
		}

		if (enterMode) {
			e.consume();
			okCallback();
		}
	}

	@Override
	public void keyReleased(KeyEvent e) {
		// don't care--keyPressed() only
	}

	public boolean getEnterMode() {
		return enterMode;
	}

	public void setEnterMode(boolean enterMode) {
		this.enterMode = enterMode;
		enterBox.setSelected(enterMode);
	}

	class PopupListener extends MouseAdapter {
		@Override
		public void mousePressed(MouseEvent e) {
			maybeShowPopup(e);
		}

		@Override
		public void mouseReleased(MouseEvent e) {
			maybeShowPopup(e);
		}

		private void maybeShowPopup(MouseEvent e) {
			if (e.isPopupTrigger()) {
				popup.show(e.getComponent(), e.getX(), e.getY());
			}
		}
	}

	class AnnotationAdapterWrapper implements Comparable<AnnotationAdapterWrapper> {
		private AnnotatedStringHandler handler;

		public AnnotationAdapterWrapper(AnnotatedStringHandler handler) {
			this.handler = handler;
		}

		@Override
		public int compareTo(AnnotationAdapterWrapper wrapper) {
			return handler.getDisplayString().compareTo(wrapper.handler.getDisplayString());
		}

		@Override
		public String toString() {
			return handler.getDisplayString();
		}

		public String getPrototypeString() {
			return handler.getPrototypeString();
		}
	}
}
