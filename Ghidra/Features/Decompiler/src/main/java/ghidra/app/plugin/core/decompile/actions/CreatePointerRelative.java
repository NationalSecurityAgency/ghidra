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
package ghidra.app.plugin.core.decompile.actions;

import java.awt.BorderLayout;
import java.util.*;

import javax.swing.*;
import javax.swing.event.CellEditorListener;

import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.label.GLabel;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.data.PointerTypedefInspector;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;
import ghidra.util.UndefinedFunction;
import ghidra.util.data.DataTypeParser;
import ghidra.util.layout.VerticalLayout;

public class CreatePointerRelative extends RetypeLocalAction {
	private DataType initialParent;
	private int initialOffset;
	private DataType userDataType = null;
	private CategoryPath userPath;
	private int userOffset;
	private String userName;
	private HighSymbol highSymbol;
	private Varnode userVarnode;
	private int pointerSize;
	private TypeDef relativePointer;

	public class RelativePointerDialog extends DataTypeSelectionDialog {
		private Program program;
		private JPanel updatedPanel;
		private JTextField offsetField;
		private JTextField nameField;

		public RelativePointerDialog(PluginTool pluginTool, Program prog) {
			super(pluginTool, prog.getDataTypeManager(), -1,
				DataTypeParser.AllowedDataTypes.FIXED_LENGTH);
			program = prog;
			DataTypeSelectionEditor editor = getEditor();

			// Remove the listener that causes a RETURN key being pressed while selecting
			// a data-type to trigger okCallback
			CellEditorListener[] listeners = editor.getCellEditorListeners();
			if (listeners.length != 0) {
				CellEditorListener lastListen = listeners[listeners.length - 1];
				editor.removeCellEditorListener(lastListen);
			}
		}

		public void setInitialOffset(int off) {
			offsetField.setText(Integer.toString(off));
		}

		public void setInitialName(String nm) {
			nameField.setText(nm);
		}

		@Override
		protected void okCallback() {
			String valueString = offsetField.getText();
			try {
				userOffset = Integer.decode(valueString);
			}
			catch (NumberFormatException ex) {
				setStatusText("Invalid offset");
				return;
			}
			userName = nameField.getText();
			String errMessage = testNameValidity(userName);
			if (errMessage != null) {
				setStatusText(errMessage);
				return;
			}
			DataTypeSelectionEditor editor = getEditor();
			try {
				if (!editor.validateUserSelection()) {
					// users can only select existing data types
					setStatusText("Unrecognized data type of \"" +
						editor.getCellEditorValueAsText() + "\" entered.");
					return;
				}
				userDataType = (DataType) editor.getCellEditorValue();
				userPath = userDataType.getCategoryPath();
				relativePointer = findPreexistingTypeDef(program);
				if (relativePointer != null) {
					if (PointerTypedefInspector
							.getPointerComponentOffset(relativePointer) != userOffset) {
						int yesno = OptionDialog.showYesNoDialog(updatedPanel,
							"Data-type already exists",
							"Data-type " + userName + " already exists with a different offset\n" +
								"and may be used in other places.\n\n" +
								"Do you want to change the offset?");
						if (yesno != 1) {
							userDataType = null;
							userPath = null;
							return;		// Don't close the dialog
						}
					}
				}
			}
			catch (InvalidDataTypeException e) {
				setStatusText(e.getMessage());
				return;
			}
			clearStatusText();
			close();
		}

		@Override
		protected JComponent createEditorPanel(DataTypeSelectionEditor dtEditor) {
			setTitle("Create Relative Pointer");

			updatedPanel = new JPanel();
			updatedPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 0));
			updatedPanel.setLayout(new VerticalLayout(5));

			JPanel dataTypePanel = new JPanel();
			dataTypePanel.setLayout(new BoxLayout(dataTypePanel, BoxLayout.LINE_AXIS));
			dataTypePanel.add(new GLabel(" Data-type:"), BorderLayout.WEST);
			dataTypePanel.add(Box.createHorizontalStrut(5));
			dataTypePanel.add(dtEditor.getEditorComponent(), BorderLayout.CENTER);

			offsetField = new JTextField();
			JPanel offsetPanel = new JPanel();
			offsetPanel.setLayout(new BoxLayout(offsetPanel, BoxLayout.LINE_AXIS));
			offsetPanel.add(new GLabel("       Offset:"), BorderLayout.WEST);
			offsetPanel.add(Box.createHorizontalStrut(5));
			offsetPanel.add(offsetField, BorderLayout.CENTER);

			nameField = new JTextField(15);
			JPanel namePanel = new JPanel();
			namePanel.setLayout(new BoxLayout(namePanel, BoxLayout.LINE_AXIS));
			namePanel.add(new GLabel("       Name:"), BorderLayout.WEST);
			namePanel.add(Box.createHorizontalStrut(5));
			namePanel.add(nameField, BorderLayout.CENTER);

			updatedPanel.add(dataTypePanel);
			updatedPanel.add(offsetPanel);
			updatedPanel.add(namePanel);

			return updatedPanel;
		}

	}

	private static class TreeSearch {
		public PcodeOp op;
		public int slot;
		public int offset;
		public Iterator<PcodeOp> iterForward;
		public DataType dataType;

		public TreeSearch(PcodeOp o, int s, int off) {
			op = o;
			slot = s;
			offset = off;
			dataType = null;
		}

		public TreeSearch(Varnode vn, int off) {
			iterForward = vn.getDescendants();
			offset = off;
			dataType = null;
		}

		public Varnode nextVarnode() {
			if (slot != 0 && op.getOpcode() != PcodeOp.MULTIEQUAL) {
				return null;
			}
			if (slot >= op.getNumInputs()) {
				return null;
			}
			Varnode res = op.getInput(slot);
			slot += 1;
			return res;
		}

		public boolean isDoneBackward(DataType origType) {
			return (dataType != null && dataType != origType && offset > 0);
		}

		public boolean isDoneForward(DataType origType) {
			return (dataType != null && dataType != origType && offset < 0);
		}

		public void stripTypeDef() {
			if (dataType instanceof TypeDef) {
				TypeDef typedef = (TypeDef) dataType;
				offset += PointerTypedefInspector.getPointerComponentOffset(typedef);
				dataType = ((Pointer) typedef.getDataType()).getDataType();
			}
		}

		public static DataType getValidDataType(Varnode vn) {
			DataType dt = vn.getHigh().getDataType();
			while (dt instanceof TypeDef) {
				TypeDef typedef = (TypeDef) dt;
				if (typedef.isPointer() &&
					PointerTypedefInspector.getPointerComponentOffset(typedef) != 0) {
					return typedef;
				}
				dt = typedef.getDataType();
			}
			if (!(dt instanceof Pointer)) {
				return null;
			}
			dt = ((Pointer) dt).getDataType();
			if (dt instanceof Structure) {
				return dt;
			}
			return null;
		}

		public static TreeSearch searchBackward(Varnode vn, int depth) {
			ArrayList<TreeSearch> stack = new ArrayList<>();
			HashSet<SequenceNumber> marked = new HashSet<>();
			TreeSearch currentNode = new TreeSearch(null, 0, 0);
			DataType origType = getValidDataType(vn);
			if (origType instanceof TypeDef) {
				origType = null;
			}
			for (;;) {
				if (vn != null) {
					currentNode.dataType = getValidDataType(vn);
					if (currentNode.isDoneBackward(origType)) {
						currentNode.stripTypeDef();
						return currentNode;
					}
					PcodeOp op = vn.getDef();
					if (op != null && stack.size() < depth && marked.add(op.getSeqnum())) {
						switch (op.getOpcode()) {
							case PcodeOp.INDIRECT:
							case PcodeOp.CAST:
							case PcodeOp.COPY:
								stack.add(new TreeSearch(op, 0, currentNode.offset));
								break;
							case PcodeOp.PTRSUB:
								stack.add(new TreeSearch(op, 0,
									currentNode.offset + (int) op.getInput(1).getOffset()));
								break;
							case PcodeOp.MULTIEQUAL:
								stack.add(new TreeSearch(op, 0, currentNode.offset));
								break;
							default:
								break;
						}
					}
				}
				if (stack.isEmpty()) {
					break;
				}
				currentNode = stack.get(stack.size() - 1);
				vn = currentNode.nextVarnode();
				if (vn == null) {
					stack.remove(stack.size() - 1);
				}
			}
			return null;
		}

		public static TreeSearch searchForward(Varnode vn, int depth) {
			ArrayList<TreeSearch> stack = new ArrayList<>();
			HashSet<SequenceNumber> marked = new HashSet<>();
			TreeSearch currentNode = new TreeSearch(vn, 0);
			stack.add(currentNode);
			DataType origType = getValidDataType(vn);
			if (origType instanceof TypeDef) {
				origType = null;
			}
			for (;;) {
				if (stack.isEmpty()) {
					break;
				}
				currentNode = stack.get(stack.size() - 1);
				if (currentNode.iterForward.hasNext()) {
					PcodeOp op = currentNode.iterForward.next();
					if (stack.size() < depth && marked.add(op.getSeqnum())) {
						TreeSearch nextNode = null;
						switch (op.getOpcode()) {
							case PcodeOp.MULTIEQUAL:
							case PcodeOp.INDIRECT:
							case PcodeOp.COPY:
							case PcodeOp.CAST:
								nextNode = new TreeSearch(op.getOutput(), currentNode.offset);
								break;
							case PcodeOp.PTRSUB:
								nextNode = new TreeSearch(op.getOutput(),
									currentNode.offset + (int) op.getInput(1).getOffset());
								break;
							case PcodeOp.PTRADD:
								if (op.getInput(1).isConstant()) {
									long off =
										op.getInput(1).getOffset() * op.getInput(2).getOffset();
									nextNode = new TreeSearch(op.getOutput(),
										currentNode.offset + (int) off);
								}
								break;
							default:
								break;
						}
						if (nextNode != null) {
							nextNode.dataType = getValidDataType(op.getOutput());
							if (nextNode.isDoneForward(origType)) {
								nextNode.stripTypeDef();
								return nextNode;
							}
							stack.add(nextNode);
						}
					}
				}
				else {
					stack.remove(stack.size() - 1);	// Pop last node
				}
			}
			return null;
		}
	}

	public CreatePointerRelative() {
		super("Create Relative Pointer");
//		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRetypeVariable"));
		setPopupMenuData(new MenuData(new String[] { "Adjust Pointer Offset" }, "Decompile"));
//		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}
		if (!tokenAtCursor.isVariableRef()) {
			return false;
		}
		HighVariable high = tokenAtCursor.getHighVariable();
		if (high == null || high.getSymbol() == null) {
			return false;
		}
		highSymbol = high.getSymbol();
		DataType dataType = high.getDataType();
		if (dataType instanceof TypeDef) {
			dataType = ((TypeDef) dataType).getBaseDataType();
		}
		return (dataType instanceof Pointer);
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		clearInfo();
		collectInitialInfo(context);
		Program program = context.getProgram();
		PluginTool tool = context.getTool();
		RelativePointerDialog dialog = new RelativePointerDialog(tool, program);
		dialog.setTabCommitsEdit(false);
		if (initialParent != null) {
			dialog.setInitialDataType(initialParent);
			dialog.setInitialOffset(initialOffset);
			dialog.setInitialName(buildDefaultName(initialParent, initialOffset));
		}
		tool.showDialog(dialog);
		if (userDataType == null) {	// Cancel
			return;
		}
		createTypeDef(program, tool);
		retypeSymbol(program, highSymbol, userVarnode, relativePointer, tool);
	}

	/**
	 * Make sure the given String works as a data-type name
	 * @param name is the given String
	 * @return an error message or null if the name is valid
	 */
	private String testNameValidity(String name) {
		if (name == null || name.length() == 0) {
			return "Must provide a name for the data-type";
		}
		return null;
	}

	/**
	 * Assuming the dialog has filled in the desired name and category of the relative pointer, as 
	 * well as the baseType, search for a preexisting TypeDef data-type that matches the name. 
	 * If no TypeDef is found return null.  If a TypeDef is found but it is not a pointer to
	 * the baseType, throw an exception. Otherwise return the TypeDef.
	 * @param program is the Program in which to search
	 * @return the matching TypeDef or null
	 * @throws InvalidDataTypeException if a mismatched TypeDef already exists
	 */
	private TypeDef findPreexistingTypeDef(Program program) throws InvalidDataTypeException {
		DataTypeManager dtm = program.getDataTypeManager();
		DataType dt = dtm.getDataType(userPath, userName);
		if (dt == null) {
			return null;
		}
		if (!(dt instanceof TypeDef)) {
			throw new InvalidDataTypeException("Data-type " + userName + " already exists");
		}
		TypeDef res = (TypeDef) dt;
		if (!(res.getDataType() instanceof Pointer)) {
			throw new InvalidDataTypeException(
				"Data-type " + userName + " already exists and is not a pointer TypeDef");
		}
		DataType baseType = ((Pointer) res.getDataType()).getDataType();
		if (!userDataType.getName().equals(baseType.getName()) ||
			!userDataType.getCategoryPath().equals(baseType.getCategoryPath())) {
			throw new InvalidDataTypeException(
				"Data-type " + userName + " already exists and has a different base");
		}
		return res;
	}

	/**
	 * Assuming the parameters have been filled in by the dialog, create the matching TypeDef.
	 * If a new TypeDef is created, or if a pointer to the base DataType already exists as a TypeDef,
	 * set the ComponentOffsetSetting to the value selected by the dialog (userOffset).
	 * @param program is the Program owning the TypeDef
	 * @param tool is the tool showing the dialog
	 */
	private void createTypeDef(Program program, PluginTool tool) {
		int transaction = program.startTransaction("Create Relative Pointer");
		try {
			if (relativePointer == null) {
				PointerDataType ptr = new PointerDataType(userDataType, pointerSize);
				TypedefDataType typedef = new TypedefDataType(userPath, userName, ptr);
				relativePointer = (TypeDef) program.getDataTypeManager().resolve(typedef, null);
			}
			ComponentOffsetSettingsDefinition.DEF.setValue(relativePointer.getDefaultSettings(),
				userOffset);
		}
		catch (IllegalArgumentException e) {
			Msg.showError(this, tool.getToolFrame(), "Relative TypeDef Failed",
				"Failed to create relative TypeDef: " + e.getMessage());
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private void clearInfo() {
		userDataType = null;
		userPath = null;
		userOffset = 0;
		userName = null;
		initialParent = null;
		initialOffset = 0;
	}

	private void collectInitialInfo(DecompilerActionContext context) {
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		HighVariable high = tokenAtCursor.getHighVariable();
		highSymbol = high.getSymbol();
		DataType dataType = high.getDataType();
		if (dataType instanceof TypeDef) {
			dataType = ((TypeDef) dataType).getBaseDataType();
		}
		if (!(dataType instanceof Pointer)) {
			return;
		}
		pointerSize = dataType.getLength();
		Varnode vn = tokenAtCursor.getVarnode();
		if (vn == null) {	// If we don't have a specific Varnode instance
			return;			// We can't search for an offset
		}
		TreeSearch node = TreeSearch.searchBackward(vn, 5);
		if (node != null) {
			initialParent = node.dataType;
			initialOffset = node.offset;
			return;
		}
		node = TreeSearch.searchForward(vn, 5);
		if (node != null) {
			initialParent = node.dataType;
			initialOffset = -node.offset;
		}
	}

	/**
	 * Build a default name for a relative pointer, given the base data-type and offset
	 * @param dt is the given base data-type
	 * @param off is the given offset
	 * @return the name
	 */
	public static String buildDefaultName(DataType dt, int off) {
		DataType inner = PcodeDataTypeManager.findPointerRelativeInner(dt, off);
		StringBuilder buffer = new StringBuilder();
		buffer.append(dt.getName());
		int val = off;
		if (val < 0) {
			buffer.append("_ptrminus_");
			val = -val;
		}
		else {
			buffer.append("_ptr_");
		}
		buffer.append(val);
		buffer.append('_').append(inner.getName());
		return buffer.toString();
	}
}
