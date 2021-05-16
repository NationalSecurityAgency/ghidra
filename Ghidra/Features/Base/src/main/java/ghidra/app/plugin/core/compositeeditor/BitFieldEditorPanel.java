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
package ghidra.app.plugin.core.compositeeditor;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;

import com.google.common.base.Predicate;

import docking.ActionContext;
import docking.widgets.DropDownSelectionTextField;
import docking.widgets.OptionDialog;
import docking.widgets.label.GDLabel;
import ghidra.app.plugin.core.compositeeditor.BitFieldPlacementComponent.BitAttributes;
import ghidra.app.plugin.core.compositeeditor.BitFieldPlacementComponent.BitFieldAllocation;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.app.util.datatype.NavigationDirection;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Composite;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.layout.*;
import resources.ResourceManager;

/**
 * <code>BitFieldEditorPanel</code> provides the ability to add or modify bitfields
 * within non-packed structures.
 */
public class BitFieldEditorPanel extends JPanel {

	private static final Icon DECREMENT_ICON = ResourceManager.loadImage("images/Minus.png");
	private static final Icon INCREMENT_ICON = ResourceManager.loadImage("images/Plus.png");

	private DataTypeManagerService dtmService;
	private Composite composite;
	private Predicate<DataType> dataTypeValidator;

	private JLabel allocationOffsetLabel;
	JButton decrementButton;
	JButton incrementButton;

	private BitFieldPlacementComponent placementComponent;
	private DataType baseDataType;

	private DataTypeSelectionEditor dtChoiceEditor;
	private JTextField fieldNameTextField;
	private JTextField fieldCommentTextField;
	private SpinnerNumberModel allocSizeModel;
	private JSpinnerWithMouseWheel allocSizeInput;
	private SpinnerNumberModel bitOffsetModel;
	private JSpinnerWithMouseWheel bitOffsetInput;
	private SpinnerNumberModel bitSizeModel;
	private JSpinnerWithMouseWheel bitSizeInput;

	private GDLabel statusTextField;

	private BitSelectionHandler bitSelectionHandler;


	private boolean updating = false;

	BitFieldEditorPanel(Composite composite, DataTypeManagerService dtmService,
			Predicate<DataType> dataTypeValidator) {
		super();
		this.composite = composite;

		if (composite.isPackingEnabled()) {
			// A different bitfield editor should be used for aligned composites
			throw new IllegalArgumentException("composite must be non-packed");
		}

		setLayout(new VerticalLayout(5));
		setFocusTraversalKeysEnabled(true);

		this.dtmService = dtmService;
		this.dataTypeValidator = dataTypeValidator;

		setBorder(BorderFactory.createEmptyBorder(5, 5, 0, 5));

		if (composite instanceof Structure) {
			add(createAllocationOffsetPanel());
		}
		add(createPlacementPanel());
		add(createLegendPanel());
		add(createEntryPanel());
		add(createStatusPanel());

		enableControls(false);
	}

	void setShowOffsetsInHex(boolean useHex) {
		placementComponent.setShowOffsetsInHex(useHex);
		updateAllocationOffsetLabel();
	}

	boolean isShowOffsetsInHex() {
		return placementComponent.isShowOffsetsInHex();
	}

	private JPanel createLegendPanel() {
		JPanel legendPanel = new JPanel(new BorderLayout());
		legendPanel.add(new BitFieldPlacementComponent.BitFieldLegend(null), BorderLayout.WEST);
		return legendPanel;
	}

	private JPanel createAllocationOffsetPanel() {

		JPanel panel = new JPanel(new HorizontalLayout(5));

		decrementButton = new JButton(DECREMENT_ICON);
		decrementButton.setFocusable(false);
		decrementButton.setToolTipText("Decrement allocation unit offset");
		decrementButton.addActionListener(e -> adjustAllocationOffset(-1));
		panel.add(decrementButton);

		incrementButton = new JButton(INCREMENT_ICON);
		incrementButton.setFocusable(false);
		incrementButton.setToolTipText("Increment allocation unit offset");
		incrementButton.addActionListener(e -> adjustAllocationOffset(1));
		panel.add(incrementButton);

		allocationOffsetLabel = new JLabel();
		allocationOffsetLabel.setHorizontalTextPosition(SwingConstants.LEFT);
		panel.add(allocationOffsetLabel);

		return panel;
	}

	private void adjustAllocationOffset(int delta) {
		int adjustedOffset = placementComponent.getAllocationOffset() + delta;
		if (adjustedOffset < 0 || adjustedOffset > composite.getLength()) {
			return;
		}
		placementComponent.updateAllocation(placementComponent.getAllocationByteSize(),
			adjustedOffset);
		updateAllocationOffsetLabel();
	}

	private void updateAllocationOffsetLabel() {
		if (composite instanceof Structure) {
			int allocOffset = placementComponent.getAllocationOffset();
			String allocOffsetStr;
			if (placementComponent.isShowOffsetsInHex()) {
				allocOffsetStr = "0x" + Integer.toHexString(allocOffset);
			}
			else {
				allocOffsetStr = Integer.toString(allocOffset);
			}
			String text =
				"Structure Offset of Allocation Unit: " + allocOffsetStr;
			allocationOffsetLabel.setText(text);

			int offset = placementComponent.getAllocationOffset();
			decrementButton.setEnabled(offset > 0);
			int length = composite.isZeroLength() ? 0 : composite.getLength();
			incrementButton.setEnabled(offset < length);
		}
	}

	private Component createStatusPanel() {
		JPanel statusPanel = new JPanel(new BorderLayout());

		statusTextField = new GDLabel(" ");
		statusTextField.setHorizontalAlignment(SwingConstants.CENTER);
		statusTextField.setForeground(Color.red);

		// use a strut panel so the size of the message area does not change if we make
		// the message label not visible
		int height = statusTextField.getPreferredSize().height;

		statusPanel.add(Box.createVerticalStrut(height), BorderLayout.WEST);
		statusPanel.add(statusTextField, BorderLayout.CENTER);

		return statusPanel;
	}

	private void setStatus(String text) {
		statusTextField.setText(text);
	}

	private void clearStatus() {
		statusTextField.setText("");
	}

	private JPanel createEntryPanel() {

		JComponent baseDataTypeEditor = createDataTypeChoiceEditor();

		fieldNameTextField = new JTextField(20);
		fieldNameTextField.setFocusable(true);

		fieldCommentTextField = new JTextField(20);
		fieldCommentTextField.setFocusable(true);

		allocSizeModel = new SpinnerNumberModel(Long.valueOf(4), Long.valueOf(1), Long.valueOf(16),
			Long.valueOf(1));
		allocSizeInput = new JSpinnerWithMouseWheel(allocSizeModel);

		bitOffsetModel = new SpinnerNumberModel(Long.valueOf(0), Long.valueOf(0), Long.valueOf(31),
			Long.valueOf(1));
		bitOffsetInput = new JSpinnerWithMouseWheel(bitOffsetModel);

		bitSizeModel = new SpinnerNumberModel(Long.valueOf(4), Long.valueOf(0), Long.valueOf(4 * 8),
			Long.valueOf(1));
		bitSizeInput = new JSpinnerWithMouseWheel(bitSizeModel);

		allocSizeModel.addChangeListener(e -> update());
		bitSizeModel.addChangeListener(e -> update());
		bitOffsetModel.addChangeListener(e -> update());

		JPanel entryPanel = new JPanel(new TwoColumnPairLayout(5, 15, 5, 0));
		entryPanel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createEtchedBorder(),
			BorderFactory.createEmptyBorder(5, 5, 5, 5)));
		entryPanel.setFocusCycleRoot(true);

		entryPanel.add(new JLabel("Base Datatype:"));
		entryPanel.add(baseDataTypeEditor);

		entryPanel.add(new JLabel("Allocation Bytes:"));
		entryPanel.add(allocSizeInput);

		entryPanel.add(new JLabel("Field Name:"));
		entryPanel.add(fieldNameTextField);

		entryPanel.add(new JLabel("Bit Size:"));
		entryPanel.add(bitSizeInput);

		entryPanel.add(new JLabel("Comment:"));
		entryPanel.add(fieldCommentTextField);

		entryPanel.add(new JLabel("Bit Offset:"));
		entryPanel.add(bitOffsetInput);
		return entryPanel;
	}

	private JComponent createDataTypeChoiceEditor() {

		dtChoiceEditor =
			new DataTypeSelectionEditor(dtmService, AllowedDataTypes.BITFIELD_BASE_TYPE);
		dtChoiceEditor.setConsumeEnterKeyPress(false);
		dtChoiceEditor.setTabCommitsEdit(true);
		//dtChoiceEditor.setPreferredDataTypeManager(composite.getDataTypeManager());

		final DropDownSelectionTextField<DataType> dtChoiceTextField =
			dtChoiceEditor.getDropDownTextField();
		dtChoiceTextField.setBorder((new JTextField()).getBorder());

		dtChoiceEditor.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				Component other = e.getOppositeComponent();
				if (other == null) {
					// Focus lost to a different application
				}
				else if (SwingUtilities.isDescendingFrom(other, BitFieldEditorPanel.this)) {
					if (!SwingUtilities.isDescendingFrom(other,
						dtChoiceEditor.getEditorComponent())) {
						dtChoiceEditor.stopCellEditing();
					}
				}
			}
		});

		dtChoiceEditor.addCellEditorListener(new CellEditorListener() {
			@Override
			public void editingCanceled(ChangeEvent e) {
				dtChoiceEditor.setCellEditorValue(baseDataType); // restore
			}

			@Override
			public void editingStopped(ChangeEvent e) {
				if (!checkValidBaseDataType()) {
					dtChoiceTextField.selectAll();
					dtChoiceTextField.requestFocus();
				}
				else {
					updateBitSizeModel();
					NavigationDirection direction = dtChoiceEditor.getNavigationDirection();
					if (direction == NavigationDirection.FORWARD) {
						allocSizeInput.requestFocus();
					}
					else if (direction == NavigationDirection.BACKWARD) {
						bitOffsetInput.requestFocus();
					}
				}
			}
		});

		dtChoiceEditor.getBrowseButton().setFocusable(false);

		JComponent editorComponent = dtChoiceEditor.getEditorComponent();
		Dimension preferredSize = editorComponent.getPreferredSize();
		editorComponent.setPreferredSize(new Dimension(200, preferredSize.height));
		return editorComponent;
	}

	private class BitSelectionHandler extends MouseAdapter {

		private boolean selectionActive = false;
		private int startBit;
		private int lastBit;
		private int lastX;

		@Override
		public void mouseClicked(MouseEvent e) {
			if (bitOffsetInput.isEnabled() || e.isConsumed() || e.getClickCount() != 2 ||
				!placementComponent.isWithinBitCell(e.getPoint())) {
				return;
			}
			BitAttributes bitAttributes = placementComponent.getBitAttributes(e.getPoint());
			if (bitAttributes != null) {
				DataTypeComponent dtc = bitAttributes.getDataTypeComponent(true);
				if (dtc == null || !dtc.isBitFieldComponent()) {
					return;
				}
				e.consume();
				initEdit(dtc, placementComponent.getAllocationOffset(), true);
			}
		}

		@Override
		public void mouseMoved(MouseEvent e) {
			if (!selectionActive && bitOffsetInput.isEnabled()) {
				boolean inBounds = placementComponent.isWithinBitCell(e.getPoint());
				setCursor(Cursor.getPredefinedCursor(
					inBounds ? Cursor.HAND_CURSOR : Cursor.DEFAULT_CURSOR));
			}
		}

		@Override
		public void mouseEntered(MouseEvent e) {
			if (!selectionActive && bitOffsetInput.isEnabled() &&
				placementComponent.isWithinBitCell(e.getPoint())) {
				setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
			}
		}

		@Override
		public void mouseExited(MouseEvent e) {
			if (!selectionActive) {
				setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
			}
		}

		@Override
		public void mousePressed(MouseEvent e) {
			if (e.isConsumed()) {
				return;
			}
			if (!placementComponent.isWithinBitCell(e.getPoint())) {
				return;
			}
			if (e.getButton() == MouseEvent.BUTTON1) {
				e.consume();
				selectionActive = false;
				if (bitOffsetInput.isEnabled()) {
					bitSizeModel.setValue(1L); // must change size first
					startBit = setBitFieldOffset(e.getPoint());
					lastBit = startBit;
					selectionActive = startBit >= 0;
					if (selectionActive) {
						lastX = e.getPoint().x;
						setCursor(Cursor.getPredefinedCursor(Cursor.W_RESIZE_CURSOR));
					}
				}
			}
		}

		@Override
		public void mouseDragged(MouseEvent e) {
			if (!selectionActive || e.isConsumed()) {
				return;
			}

			e.consume();

			Point p = e.getPoint();

			if (p.x == lastX) {
				return;
			}
			Cursor cursor = Cursor.getPredefinedCursor(
				p.x < lastX ? Cursor.W_RESIZE_CURSOR : Cursor.E_RESIZE_CURSOR);
			setCursor(cursor);
			lastX = p.x;

			int bitOffset = placementComponent.getBitOffset(p);
			if (bitOffset == lastBit) {
				return;
			}

			// ensure that scroll region keeps mouse point visible
			if (!placementComponent.getVisibleRect().contains(p)) {
				BitAttributes bitAttributes = placementComponent.getBitAttributes(e.getPoint());
				if (bitAttributes != null) {
					placementComponent.scrollRectToVisible(bitAttributes.getRectangle());
				}
			}

			if (bitOffset >= 0) {
				// NOTE: spinner models require use of long values
				lastBit = bitOffset;
				if (bitOffset <= startBit) {
					int start = Math.min(startBit, bitOffset);
					bitOffsetModel.setValue((long) start);
				}
				long bitSize = Math.abs(bitOffset - startBit) + 1;
				bitSizeModel.setValue(bitSize);
			}
		}

		@Override
		public void mouseReleased(MouseEvent e) {
			if (selectionActive && !e.isConsumed()) {
				e.consume();
				selectionActive = false;

				Point p = e.getPoint();
				boolean inBounds = placementComponent.getVisibleRect().contains(p);
				setCursor(Cursor.getPredefinedCursor(
					inBounds ? Cursor.HAND_CURSOR : Cursor.DEFAULT_CURSOR));
			}
		}

	}

	private JPanel createPlacementPanel() {

		placementComponent = new BitFieldPlacementComponent(composite, true);
		placementComponent.setFont(UIManager.getFont("TextField.font"));
		placementComponent.addMouseWheelListener(e -> bitSizeInput.mouseWheelMoved(e));

		bitSelectionHandler = new BitSelectionHandler();
		placementComponent.addMouseListener(bitSelectionHandler);
		placementComponent.addMouseMotionListener(bitSelectionHandler);

		JPanel bitViewPanel = new JPanel(new PairLayout(0, 5));

		JPanel labelPanel = new JPanel(new VerticalLayout(5));
		labelPanel.setBorder(BorderFactory.createEmptyBorder(7, 5, 0, 0));
		JLabel byteOffsetLabel = new JLabel("Byte Offset:", SwingConstants.RIGHT);
		labelPanel.add(byteOffsetLabel);
		labelPanel.add(new JLabel("Component Bits:", SwingConstants.RIGHT));
		bitViewPanel.add(labelPanel);

		JScrollPane scrollPane =
			new JScrollPane(placementComponent, ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		scrollPane.getViewport().setBackground(getBackground());
		scrollPane.setBorder(null);

		bitViewPanel.add(scrollPane);
		return bitViewPanel;
	}

	private boolean checkValidBaseDataType() {
		DropDownSelectionTextField<DataType> textField = dtChoiceEditor.getDropDownTextField();
		String dtName = textField.getText().trim();
		boolean isValid = true;
		try {
			if (dtName.length() == 0 || !dtChoiceEditor.validateUserSelection()) {
				setStatus("Valid bitfield base datatype entry required");
				isValid = false;
			}
		}
		catch (InvalidDataTypeException e) {
			setStatus("Invalid bitfield base datatype: " + e.getMessage());
			isValid = false;
		}
		if (isValid) {
			DataType dt = dtChoiceEditor.getCellEditorValueAsDataType();
			if (!dataTypeValidator.apply(baseDataType)) {
				setStatus("Valid bitfield base datatype entry required");
				isValid = false;
			}
			else {
				baseDataType = dt.clone(composite.getDataTypeManager());
				clearStatus();
			}
		}
		else {
			dataTypeValidator.apply(null); // affects button enablement
		}
		return isValid;
	}

	void initAdd(DataType initialBaseDataType, int allocationOffset, int bitOffset,
			boolean useCurrentAllocation) {
		if (initialBaseDataType == null) {
			initialBaseDataType = baseDataType;
		}
		if (!BitFieldDataType.isValidBaseDataType(initialBaseDataType)) {
			initialBaseDataType = IntegerDataType.dataType.clone(composite.getDataTypeManager());
		}
		long allocationSize = useCurrentAllocation ? (Long) allocSizeModel.getValue()
				: initialBaseDataType.getLength();
		placementComponent.updateAllocation((int) allocationSize, allocationOffset);
		placementComponent.initAdd(1, bitOffset);
		initControls(null, null, initialBaseDataType, 1);
		enableControls(true);
	}

	/**
	 * Initialize for edit of existing component or no component if bitfieldDtc is null.
	 * If null an allocation size of 4-bytes will be used but may be adjusted.
	 * @param bitfieldDtc bitfield component or null
	 * @param allocationOffset allocation offset to be used
	 * @param useExistingAllocationSize if true attempt to use existing allocation size
	 */
	void initEdit(DataTypeComponent bitfieldDtc, int allocationOffset,
			boolean useExistingAllocationSize) {
		String initialFieldName = null;
		String initialComment = null;
		DataType initialBaseDataType = null;
		int allocationSize = -1;
		if (useExistingAllocationSize) {
			allocationSize = placementComponent.getAllocationByteSize();
		}
		if (bitfieldDtc != null) {
			if (!bitfieldDtc.isBitFieldComponent()) {
				throw new IllegalArgumentException("unsupport data type component");
			}
			initialFieldName = bitfieldDtc.getFieldName();
			initialComment = bitfieldDtc.getComment();
			BitFieldDataType bitfieldDt = (BitFieldDataType) bitfieldDtc.getDataType();
			initialBaseDataType = bitfieldDt.getBaseDataType();
			if (allocationSize < 1) {
				allocationSize = initialBaseDataType.getLength();
			}
			int allocationAdjust = composite.getLength() - allocationOffset - allocationSize;
			if (allocationAdjust < 0) {
				allocationSize += allocationAdjust;
			}
		}
		if (allocationSize < 1) {
			allocationSize = 4;
		}
		placementComponent.updateAllocation(allocationSize, allocationOffset);
		placementComponent.init(bitfieldDtc);
		BitFieldAllocation bitFieldAllocation = placementComponent.getBitFieldAllocation(); // get updated instance
		initControls(initialFieldName, initialComment, initialBaseDataType,
			bitFieldAllocation.getBitSize());
		enableControls(bitfieldDtc != null);
	}

	void componentDeleted(int ordinal) {
		placementComponent.componentDeleted(ordinal);
	}

	private void initControls(String initialFieldName, String initialComment,
			DataType initialBaseDataType, int initialBitSize) {
		updating = true;
		try {
			baseDataType = initialBaseDataType;
			dataTypeValidator.apply(baseDataType);
			dtChoiceEditor.setCellEditorValue(initialBaseDataType);
			fieldNameTextField.setText(initialFieldName);
			fieldCommentTextField.setText(initialComment);

			// Use current placementComponent to obtain initial values
			allocSizeModel.setValue((long) placementComponent.getAllocationByteSize());
			int allocBits = 8 * placementComponent.getAllocationByteSize();
			bitSizeModel.setValue((long) initialBitSize);
			bitOffsetModel.setMaximum((long) allocBits - 1);
			BitFieldAllocation bitFieldAllocation = placementComponent.getBitFieldAllocation();
			bitOffsetModel.setValue((long) bitFieldAllocation.getBitOffset());
			updateBitSizeModel();

			updateAllocationOffsetLabel();
		}
		finally {
			updating = false;
		}
	}

	/**
	 * @return true if actively editing or adding a bitfield
	 */
	boolean isEditing() {
		return placementComponent.isEditing();
	}

	/**
	 * @return true if actively adding a bitfield
	 */
	boolean isAdding() {
		return placementComponent.isAdding();
	}

	boolean endCurrentEdit() {
		if (placementComponent.isEditing()) {
//			String currentOp = placementComponent.isAdding() ? "add" : "edit";
//			int option = OptionDialog.showYesNoDialog(this, "Confirm Edit Action",
//				"Cancel current bitfield " + currentOp + " operation?");
//			if (option != OptionDialog.YES_OPTION) {
//				return false;
//			}
			placementComponent.cancelEdit();
			enableControls(false);
		}
		return true;
	}

	boolean apply(CompositeChangeListener listener) {

		if (!checkValidBaseDataType()) {
			DropDownSelectionTextField<DataType> dtChoiceTextField =
				dtChoiceEditor.getDropDownTextField();
			dtChoiceTextField.selectAll();
			dtChoiceTextField.requestFocus();
			return false;
		}

		boolean deleteConflicts = false;
		if (placementComponent.hasApplyConflict()) {
			long allocationSize = (Long) allocSizeModel.getValue();
			int option = OptionDialog.showOptionDialog(this, "Bitfield Conflict(s)",
				"Bitfield placement conflicts with one or more components.\n" +
					"Would you like to delete conflicts or move conflicts by " + allocationSize +
					" bytes?",
				"Delete Conflicts", "Move Conflicts", OptionDialog.WARNING_MESSAGE);
			if (option == OptionDialog.CANCEL_OPTION) {
				return false;
			}
			deleteConflicts = (option == OptionDialog.OPTION_ONE);
		}
		placementComponent.applyBitField(baseDataType, fieldNameTextField.getText().trim(),
			fieldCommentTextField.getText().trim(), deleteConflicts, listener);
		enableControls(false);
		return true;
	}

	private void enableControls(boolean enable) {
		dtChoiceEditor.getBrowseButton().setEnabled(enable);
		dtChoiceEditor.getDropDownTextField().setEnabled(enable);
		fieldNameTextField.setEnabled(enable);
		fieldCommentTextField.setEnabled(enable);
		allocSizeInput.setEnabled(enable);
		bitSizeInput.setEnabled(enable);
		bitOffsetInput.setEnabled(enable);
		if (!enable) {
			// TODO: set placementComponent mode to NONE
			dtChoiceEditor.getDropDownTextField().setText("");
			fieldNameTextField.setText(null);
			fieldCommentTextField.setText(null);

			bitOffsetModel.setValue(0L);
			bitSizeModel.setValue(1L);
		}
	}

	private int setBitFieldOffset(Point point) {
		int bitOffset = placementComponent.getBitOffset(point);
		if (bitOffset >= 0) {
			// long cast is required for auto-box to Long object
			bitOffsetModel.setValue((long) bitOffset);
		}
		return bitOffset;
	}

	private DataTypeComponent getDataTypeComponent(Point p) {
		BitAttributes attrs = placementComponent.getBitAttributes(p);
		if (attrs != null) {
			return attrs.getDataTypeComponent(true);
		}
		return null;
	}

	private void updateBitSizeModel() {
		int allocSize = allocSizeModel.getNumber().intValue();
		int allocBits = 8 * allocSize;
		int baseTypeBits = baseDataType != null ? (8 * baseDataType.getLength()) : allocBits;
		long maxBitSize = Math.min(allocBits, baseTypeBits);
		bitSizeModel.setMaximum(maxBitSize);
		if (maxBitSize < (Long) bitSizeModel.getValue()) {
			bitSizeModel.setValue(maxBitSize);
		}
	}

	private void update() {
		if (updating) {
			return;
		}
		updating = true;
		try {
			int allocSize = allocSizeModel.getNumber().intValue();
			int allocBits = 8 * allocSize;
			updateBitSizeModel();
			bitOffsetModel.setMaximum(Long.valueOf(allocBits - 1));
			int bitSize = bitSizeModel.getNumber().intValue();

			int boff = bitOffsetModel.getNumber().intValue();
			int total = bitSize + boff;
			if (total > allocBits) {
				boff -= total - allocBits;
				if (boff < 0) {
					boff = 0;
				}
			}
			if (bitSize == 0) {
				// force preferred placement of zero-length bit-field
				//   little-endian: lsb of byte
				//   big-endian: msb of byte
				boff = 8 * (boff / 8);
				if (placementComponent.isBigEndian()) {
					boff += 7;
				}
				bitOffsetModel.setStepSize((long) 8);
			}
			else {
				bitOffsetModel.setStepSize((long) 1);
			}
			bitOffsetModel.setValue(Long.valueOf(boff));
			if (bitSize > allocBits) {
				bitSize = allocBits;
				bitSizeModel.setValue(Long.valueOf(bitSize));
			}
			placementComponent.refresh(allocSize, placementComponent.getAllocationOffset(), bitSize,
				boff);
		}
		finally {
			updating = false;
		}
	}

	ActionContext getActionContext(MouseEvent event) {
		if (placementComponent == event.getSource()) {
			Point p = event.getPoint();
			return new BitFieldEditorContext(getDataTypeComponent(p),
				placementComponent.getBitOffset(p));
		}
		return null;
	}

	class BitFieldEditorContext extends ActionContext {

		private int selectedBitOffset;
		private DataTypeComponent selectedDtc;

		private BitFieldEditorContext(DataTypeComponent selectedDtc, int selectedBitOffset) {
			this.selectedDtc = selectedDtc;
			this.selectedBitOffset = selectedBitOffset;
		}

		DataTypeComponent getSelectedComponent() {
			return selectedDtc;
		}

		public int getAllocationOffset() {
			return placementComponent.getAllocationOffset();
		}

		public int getSelectedBitOffset() {
			return selectedBitOffset;
		}

	}

	private static class JSpinnerWithMouseWheel extends JSpinner implements MouseWheelListener {

		JSpinnerWithMouseWheel(SpinnerNumberModel model) {
			super(model);
			addMouseWheelListener(this);
		}

		@Override
		public void requestFocus() {
			DefaultEditor editor = (DefaultEditor) getEditor();
			editor.getTextField().requestFocus();
		}

		@Override
		public void mouseWheelMoved(MouseWheelEvent mwe) {
			if (!isEnabled() || mwe.getModifiersEx() != 0 || mwe.isConsumed()) {
				return;
			}
			if (mwe.getScrollType() != MouseWheelEvent.WHEEL_UNIT_SCROLL) {
				// TODO: should we handle other modes?
				return;
			}
			mwe.consume();
			SpinnerNumberModel m = (SpinnerNumberModel) getModel();
			Long value =
				mwe.getUnitsToScroll() > 0 ? (Long) m.getPreviousValue() : (Long) m.getNextValue();
			if (value != null) {
				setValue(value);
			}
		}
	}
}
