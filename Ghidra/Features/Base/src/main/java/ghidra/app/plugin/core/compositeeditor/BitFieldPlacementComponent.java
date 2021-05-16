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
import java.util.*;

import javax.help.UnsupportedOperationException;
import javax.swing.*;

import ghidra.program.model.data.*;
import ghidra.program.model.data.Composite;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.layout.VerticalLayout;
import resources.icons.ColorIcon;

public class BitFieldPlacementComponent extends JPanel implements Scrollable {

	private static final int CELL_HEIGHT = 25;
	private static final int ZERO_BIT_WIDTH = 3;
	private static final int BIT_SEPARATOR_THICKNESS = 1;
	private static final int BYTE_SEPARATOR_THICKNESS = 2;
	private static final int SCROLLBAR_THICKNESS = 15;
	private static final int MY_HEIGHT = (2 * CELL_HEIGHT) + (3 * BYTE_SEPARATOR_THICKNESS);
	private static final int BYTE_ROW_HEIGHT = CELL_HEIGHT + (2 * BYTE_SEPARATOR_THICKNESS);

	private static final int LENEND_BOX_SIZE = 16;

	private static final Color TEXT_COLOR = Color.black;
	private static final Color LINE_COLOR = Color.black;
	private static final Color BYTE_HEADER_COLOR = new Color(0xdfdfdf);
	private static final Color UNDEFINED_BIT_COLOR = new Color(0xf8f8f8);
	private static final Color ACTIVE_BITFIELD_BITS_COLOR = Color.green;
	private static final Color CONFLICT_BITS_COLOR = Color.yellow;
	private static final Color BITFIELD_COMPONENT_COLOR = new Color(0xbfbfff);
	private static final Color NON_BITFIELD_COMPONENT_COLOR = new Color(0xa0a0ff);
	private static final Color INTERIOR_LINE_COLOR = new Color(0xd4d4d4);

	private int bitWidth = 10;
	private int byteWidth = getByteWidth(bitWidth);

	private final boolean editUseEnabled;

	private Composite composite;
	private boolean bigEndian;

	private int allocationByteOffset;
	private int allocationByteSize = 1;
	private BitFieldAllocation bitFieldAllocation;

	private EditMode editMode = EditMode.NONE;
	private int editOrdinal = -1;
	private DataTypeComponent editComponent;
	private boolean showOffsetsInHex = false;

	public static class BitFieldLegend extends JPanel {

		BitFieldLegend(DataTypeComponent viewedBitfield) {
			JPanel legendPanel;
			if (viewedBitfield != null) {
				setLayout(new VerticalLayout(10));
				legendPanel = new JPanel(new GridLayout(1, 3, 5, 5));
				String viewComponentText =
					"Selected bitfield  { " + viewedBitfield.getDataType().getDisplayName();
				String viewComponentName = viewedBitfield.getFieldName();
				if (viewComponentName != null) {
					viewComponentText += "  " + viewComponentName;
				}
				viewComponentText += " }";
				add(new JLabel(viewComponentText,
					new ColorIcon(ACTIVE_BITFIELD_BITS_COLOR, INTERIOR_LINE_COLOR, LENEND_BOX_SIZE),
					SwingConstants.LEFT));
				add(legendPanel);
			}
			else {
				setLayout(new GridLayout(2, 3, 5, 5));
				legendPanel = this;
			}

			legendPanel.add(new JLabel("Defined bitfield",
				new ColorIcon(BITFIELD_COMPONENT_COLOR, INTERIOR_LINE_COLOR, LENEND_BOX_SIZE),
				SwingConstants.LEFT));
			legendPanel.add(new JLabel("Defined non-bitfield  ",
				new ColorIcon(NON_BITFIELD_COMPONENT_COLOR, INTERIOR_LINE_COLOR, LENEND_BOX_SIZE),
				SwingConstants.LEFT));
			legendPanel.add(new JLabel("Undefined bits",
				new ColorIcon(UNDEFINED_BIT_COLOR, INTERIOR_LINE_COLOR, LENEND_BOX_SIZE),
				SwingConstants.LEFT));

			if (viewedBitfield == null) {
				legendPanel.add(new JLabel("Edit bitfield bits",
					new ColorIcon(ACTIVE_BITFIELD_BITS_COLOR, INTERIOR_LINE_COLOR, LENEND_BOX_SIZE),
					SwingConstants.LEFT));
				legendPanel.add(new JLabel("Conflict bits",
					new ColorIcon(CONFLICT_BITS_COLOR, INTERIOR_LINE_COLOR, LENEND_BOX_SIZE),
					SwingConstants.LEFT));
			}
		}

	}

	/**
	 * Construct a bit field viewer/editor component.  Non-edit use limits bit
	 * attribute computation to visible range only which facilitate use within
	 * scroll pane for very large structures.  Edit use will determine bit attributes
	 * for full allocation size. 
	 * @param composite composite data type to be viewed/modified.
	 * @param editUseEnabled if true use of editing bitfield editing/placement is
	 * supported, else viewing only.
	 */
	BitFieldPlacementComponent(Composite composite, boolean editUseEnabled) {
		this.composite = composite;
		this.editUseEnabled = editUseEnabled;
		if (composite != null) {
			bigEndian = composite.getDataOrganization().isBigEndian();
		}
		updatePreferredSize();
		setSize(getPreferredSize());
		setMinimumSize(getPreferredSize());
		ToolTipManager.sharedInstance().registerComponent(this);
		addMouseWheelListener(new MyMouseWheelListener());
	}

	/**
	 * Get the composite associated with this component.
	 * @return composite or null
	 */
	public Composite getComposite() {
		return composite;
	}

	/**
	 * Set the current composite.  State will reset to a non-edit mode.
	 * The edit use enablement will remain unchanged.
	 * @param composite composite or null
	 */
	public void setComposite(Composite composite) {
		this.composite = composite;
		if (composite != null) {
			bigEndian = composite.getDataOrganization().isBigEndian();
		}
		allocationByteOffset = 0;
		allocationByteSize = 1;
		if (!editUseEnabled && composite != null) {
			allocationByteSize = composite.getLength();
		}
		init(null);
	}

	public void setShowOffsetsInHex(boolean useHex) {
		this.showOffsetsInHex = useHex;
		if (bitFieldAllocation != null) {
			bitFieldAllocation.refresh(true);
			repaint();
		}
	}

	public boolean isShowOffsetsInHex() {
		return showOffsetsInHex;
	}

	@Override
	public Dimension getPreferredScrollableViewportSize() {
		return getPreferredSize();
	}

	@Override
	public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
		// NOTE: consider forcing visibleRect edge alignment to byte boundary based upon direction
		return byteWidth;
	}

	@Override
	public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
		// NOTE: consider forcing visibleRect edge alignment to byte boundary based upon direction
		return visibleRect.width;
	}

	@Override
	public boolean getScrollableTracksViewportWidth() {
		return false;
	}

	@Override
	public boolean getScrollableTracksViewportHeight() {
		return true;
	}

	private class MyMouseWheelListener implements MouseWheelListener {

		@Override
		public void mouseWheelMoved(MouseWheelEvent e) {
			if (bitFieldAllocation == null || e.getModifiersEx() != InputEvent.SHIFT_DOWN_MASK ||
				e.isConsumed()) {
				return;
			}
			if (e.getScrollType() != MouseWheelEvent.WHEEL_UNIT_SCROLL) {
				// TODO: should we handle other modes?
				return;
			}
			e.consume();

			Point p = e.getPoint();
			int index = getBitIndex(p.x);
			if (index < 0) {
				return;
			}

			int w = bitWidth + e.getWheelRotation();
			if (w >= 10) {
				Rectangle visibleRect = getVisibleRect();
				double offsetX = p.getX() - visibleRect.getX();

				setBitWidth(w);

				Rectangle bitRec = bitFieldAllocation.bitAttributes[index].rectangle;
				int x = (int) (bitRec.getCenterX() - offsetX);
				Rectangle r =
					new Rectangle(x, visibleRect.y, visibleRect.width, visibleRect.height);

				scrollRectToVisible(r);
			}
		}

	}

	private static int getByteWidth(int bitWidth) {
		return 8 * (bitWidth + BIT_SEPARATOR_THICKNESS);
	}

	void setBitWidth(int width) {

		bitWidth = width;
		byteWidth = getByteWidth(bitWidth);
		if (bitFieldAllocation != null) {
			bitFieldAllocation.layoutBits();
		}
		updatePreferredSize();
		repaint();
	}

	/**
	 * @return fixed height of component
	 */
	public int getPreferredHeight() {
		return MY_HEIGHT + SCROLLBAR_THICKNESS;
	}

	/**
	 * Determine if specified point is within bit cell region
	 * @param p point within this component's bounds
	 * @return true if p is within bit cell region
	 */
	public boolean isWithinBitCell(Point p) {
		return p.y < MY_HEIGHT && p.y > BYTE_ROW_HEIGHT;
	}

	private int getPreferredWidth() {
		int extraLineSpace = BYTE_SEPARATOR_THICKNESS - BIT_SEPARATOR_THICKNESS;
		return (allocationByteSize * byteWidth) + BYTE_SEPARATOR_THICKNESS + extraLineSpace;
	}

	boolean isBigEndian() {
		return bigEndian;
	}

	BitFieldAllocation getBitFieldAllocation() {
		return bitFieldAllocation;
	}

	int getBitOffset(Point point) {
		int bitWidthWithLine = bitWidth + BIT_SEPARATOR_THICKNESS;
		int cellIndex = (point.x - BYTE_SEPARATOR_THICKNESS) / bitWidthWithLine;
		return (8 * allocationByteSize) - cellIndex - 1;
	}

	private void updatePreferredSize() {
		setPreferredSize(new Dimension(getPreferredWidth(), getPreferredHeight()));
		revalidate();
	}

	/**
	 * Refresh the bitfield allocation following an {@link #editMode} change.
	 * When {@link #editMode} is not {@link EditMode#NONE} the specified
	 * bitSize and bitOffset specify the active edit bitfield.
	 * @param bitSize component bitsize
	 * @param bitOffset component lsb bit offset from lsb of allocation unit 
	 * (allocation unit size is determine by current {@link #allocationByteSize}).
	 */
	void refresh(int bitSize, int bitOffset) {
		bitFieldAllocation = new BitFieldAllocation(bitSize, bitOffset);
		updatePreferredSize();
		repaint();
	}

	/**
	 * Refresh the bitfield allocation following an {@link #editMode} change or
	 * change in allocation unit size/offset.
	 * When {@link #editMode} is not {@link EditMode#NONE} the specified
	 * bitSize and bitOffset specify the active edit bitfield.
	 * @param byteSize allocation unit byte size
	 * @param byteOffset allocation unit byte offset within composite
	 * @param bitSize component bitsize
	 * @param bitOffset component lsb bit offset from lsb of allocation unit.
	 */
	void refresh(int byteSize, int byteOffset, int bitSize, int bitOffset) {
		this.allocationByteOffset = byteOffset;
		this.allocationByteSize = byteSize;
		bitFieldAllocation = new BitFieldAllocation(bitSize, bitOffset);
		updatePreferredSize();
		repaint();
	}

	/**
	 * Update the size and offset of the allocation unit.  Since this can 
	 * affect the size of this component, its bounds will be updated the component
	 * repainted.
	 * @param byteSize allocation byte size
	 * @param byteOffset offset of allocation from start of composite
	 */
	void updateAllocation(int byteSize, int byteOffset) {
		this.allocationByteOffset = byteOffset;
		this.allocationByteSize = byteSize;
		setBounds(0, 0, getPreferredWidth(), getPreferredHeight());
		invalidate();
		if (bitFieldAllocation != null) {
			if (editMode == EditMode.EDIT && editComponent.getOffset() > composite.getLength()) {
				editMode = EditMode.NONE;
				editOrdinal = -1;
				editComponent = null;
			}
			bitFieldAllocation.refresh(true);
			repaint();
		}
	}

	int getAllocationOffset() {
		return allocationByteOffset;
	}

	int getAllocationByteSize() {
		return allocationByteSize;
	}

	void initAdd(int bitSize, int bitOffset) {
		if (!editUseEnabled) {
			throw new IllegalStateException("component not constructed for edit use");
		}
		editMode = EditMode.ADD;
		editOrdinal = -1;
		editComponent = null;
		refresh(bitSize, bitOffset);
	}

	void init(DataTypeComponent editDtc) {

		if (editDtc == null || editDtc.isFlexibleArrayComponent()) {
			editMode = EditMode.NONE;
			editOrdinal = -1;
			this.editComponent = null;
			refresh(0, 0);
			return;
		}

		editMode = EditMode.EDIT;
		editOrdinal = editDtc.getOrdinal();
		this.editComponent = editDtc;

		BitFieldPlacement placement = new BitFieldPlacement(editDtc);
		int bitSize = placement.zeroBitField ? 0 : (placement.rightBit - placement.leftBit + 1);
		bitFieldAllocation =
			new BitFieldAllocation(bitSize, (8 * allocationByteSize) - placement.rightBit - 1);
		updatePreferredSize();
		repaint();
	}

	boolean hasApplyConflict() {
		if (!editUseEnabled) {
			throw new IllegalStateException("component not constructed for edit use");
		}
		if (composite == null || bitFieldAllocation == null) {
			throw new IllegalStateException();
		}
		if (composite instanceof Union) {
			return false;
		}
		return bitFieldAllocation.hasConflict;
	}

	/**
	 * @return true if editing or adding a bitfield
	 */
	boolean isEditing() {
		return editUseEnabled && editMode != EditMode.NONE;
	}

	/**
	 * @return true if adding a bitfield
	 */
	boolean isAdding() {
		return editMode == EditMode.ADD;
	}

	void cancelEdit() {
		if (editMode != EditMode.NONE) {
			editMode = EditMode.NONE;
			editOrdinal = -1;
			refresh(0, 0);
		}
	}

	void componentDeleted(int ordinal) {
		if (editMode == EditMode.EDIT) {
			if (ordinal == editOrdinal) {
				// unexpected removal
				editMode = EditMode.ADD;
				editOrdinal = -1;
				editComponent = null;
			}
			else if (ordinal < editOrdinal) {
				--editOrdinal;
			}
		}
		bitFieldAllocation.refresh(true);
		repaint();
	}

	void applyBitField(DataType baseDataType, String fieldName, String fieldComment,
			boolean deleteConflicts, CompositeChangeListener listener) {
		if (!editUseEnabled) {
			throw new IllegalStateException("component not constructed for edit use");
		}
		if (composite == null) {
			throw new IllegalStateException("Composite not loaded");
		}
		HashSet<Integer> ordinalDeleteSet = new HashSet<>();
		if (editOrdinal >= 0) {
			int initialLength = composite.getLength();

			composite.delete(editOrdinal);

			int sizeChange = initialLength - composite.getLength();
			if (!composite.isPackingEnabled() && editOrdinal < composite.getNumComponents()) {
				// deletions cause shift which is bad - pad with defaults
				for (int i = 0; i < sizeChange; i++) {
					composite.insert(editOrdinal, DataType.DEFAULT);
				}
			}
		}
		if (deleteConflicts) {
			for (BitAttributes attrs : bitFieldAllocation.bitAttributes) {
				if (attrs.hasConflict() && (attrs.isAddBitField() || attrs.isEditField())) {
					// Edit component will always be on top of conflict
					ordinalDeleteSet.add(attrs.getConflict().getOrdinal());
				}
			}
		}
		Integer[] ordinalsToDelete = ordinalDeleteSet.toArray(new Integer[ordinalDeleteSet.size()]);
		Arrays.sort(ordinalsToDelete); // delete from end first
		int ordinal = composite.getNumComponents();
		for (int i = ordinalsToDelete.length - 1; i >= 0; i--) {
			ordinal = ordinalsToDelete[i];
			composite.delete(ordinal);
		}

		try {
			String name = (fieldName != null && fieldName.length() != 0) ? fieldName : null;
			String comment =
				(fieldComment != null && fieldComment.length() != 0) ? fieldComment : null;
			DataTypeComponent dtc;
			if (composite instanceof Union) {
				throw new UnsupportedOperationException(
					"Union modification not currently supported");
//				dtc = composite.insertBitField(ordinal, allocationByteSize,
//					bitFieldAllocation.bitOffset, baseDataType, bitFieldAllocation.bitSize, name,
//					comment);
			}
//			else {
			Structure struct = (Structure) composite;
			dtc = struct.insertBitFieldAt(allocationByteOffset, allocationByteSize,
				bitFieldAllocation.bitOffset, baseDataType, bitFieldAllocation.bitSize, name,
				comment);
//			}
			if (listener != null) {
				listener.componentChanged(dtc.getOrdinal());
			}
		}
		catch (ArrayIndexOutOfBoundsException | InvalidDataTypeException e) {
			Msg.error(this, "Unexpected bitfield apply error", e);
		}
		finally {
			editMode = EditMode.NONE;
			editOrdinal = -1;
			editComponent = null;
			bitFieldAllocation.refresh(true);
			repaint();
		}
	}

	private static Comparator<Object> bitAttributesXComparator = (o1, o2) -> {
		BitAttributes attrs = (BitAttributes) o1;
		int x = (Integer) o2;
		if (attrs.rectangle == null) {
			return -1;
		}
		if (x >= attrs.rectangle.x && x < (attrs.rectangle.x + attrs.rectangle.width)) {
			return 0;
		}
		return attrs.rectangle.x - x;
	};

	/**
	 * Get the bit attributes object which corresponds to the specified point p within the
	 * bounds of this component. NOTE: use of non-visible bitAttributes within the 
	 * allocation range requires edit use enablement (see {@link #editUseEnabled}).
	 * @param p point within the bounds of this component
	 * @return bit attributes object or null
	 */
	BitAttributes getBitAttributes(Point p) {
		if (bitFieldAllocation == null) {
			return null;
		}
		int index = Arrays.binarySearch(bitFieldAllocation.bitAttributes, (Integer) p.x,
			bitAttributesXComparator);
		if (index >= 0) {
			return bitFieldAllocation.bitAttributes[index];
		}
		return null;
	}

	/**
	 * Get the bit attributes index which corresponds to the specified horizontal x position 
	 * within the bounds of this component.
	 * @param x horizontal x position within the bounds of this component
	 * @return bit attributes index or -1 if not found
	 */
	int getBitIndex(int x) {
		if (bitFieldAllocation == null) {
			return -1;
		}
		int index = Arrays.binarySearch(bitFieldAllocation.bitAttributes, (Integer) x,
			bitAttributesXComparator);
		if (index >= 0) {
			return index;
		}
		return -1;
	}

	/**
	 * Get rectangle which fully encompasses specified component bytes.
	 * @param dtc data type component
	 * @return component rectangle or null
	 */
	Rectangle getComponentRectangle(DataTypeComponent dtc) {
		if (bitFieldAllocation == null || dtc == null) {
			return null;
		}

		// compute rectangle which extends to byte boundary
		int offset = (dtc.getOffset() - allocationByteOffset);
		if (!bigEndian) {
			offset = allocationByteSize - offset - dtc.getLength();
		}
		int x = offset * byteWidth;
		int y = (2 * BYTE_SEPARATOR_THICKNESS) + CELL_HEIGHT;
		int width = (dtc.getLength() * byteWidth) + (2 * BYTE_SEPARATOR_THICKNESS);
		return new Rectangle(x, y, width, CELL_HEIGHT);
	}

	@Override
	public String getToolTipText(MouseEvent e) {
		BitAttributes attrs = getBitAttributes(e.getPoint());
		if (attrs == null) {
			return null;
		}
		String tip = attrs.getTip();
		if (tip == null) {
			return null;
		}
		String conflictMsg = "";
		DataTypeComponent conflict = attrs.getConflict();
		if (conflict != null) {
			if (tip.length() != 0) {
				conflictMsg = "<br>";
			}
			String conflictName = conflict.getFieldName();
			String conflictTip = "'" + conflict.getDataType().getDisplayName() +
				(conflictName != null ? (" " + conflictName) : "") + "' at offset " +
				conflict.getOffset();
			conflictMsg += "<div style=\"color: red;font-style: italic\">conflict with " +
				HTMLUtilities.escapeHTML(conflictTip) + "</div>";
		}
		return "<HTML><div style=\"text-align:center\">" + HTMLUtilities.escapeHTML(tip) +
			conflictMsg +
			"<div style=\"color: gray;font-style: italic\">(Shift-wheel to zoom)</div></div></HTML>";
	}

	@Override
	public void paintComponent(Graphics g) {

		int height = getHeight();
		int width = getWidth();

		g.setColor(getBackground());
		g.fillRect(0, 0, width, height);

		if (bitFieldAllocation == null) {
			return;
		}

		width = getPreferredWidth();
		height = MY_HEIGHT;

		g.setColor(LINE_COLOR);
		g.fillRect(0, 0, width, BYTE_SEPARATOR_THICKNESS); // top line
		g.fillRect(0, 0, BYTE_SEPARATOR_THICKNESS, height); // left line (full height)
		g.fillRect(width - BYTE_SEPARATOR_THICKNESS, 0, BYTE_SEPARATOR_THICKNESS, height); // right line (full height)
		int y = CELL_HEIGHT + BYTE_SEPARATOR_THICKNESS;
		g.fillRect(0, y, width, BYTE_SEPARATOR_THICKNESS); // next horizontal line
		y += CELL_HEIGHT + BYTE_SEPARATOR_THICKNESS;
		g.fillRect(0, y, width, BYTE_SEPARATOR_THICKNESS); // bottom line

		paintByteHeader(g, BYTE_SEPARATOR_THICKNESS, allocationByteOffset);
		paintBits((Graphics2D) g, (2 * BYTE_SEPARATOR_THICKNESS) + CELL_HEIGHT);
	}

	private void paintByteHeader(Graphics g, int y, int baseOffset) {
		int byteSize = allocationByteSize;
		int x = BYTE_SEPARATOR_THICKNESS;

		// start close to the left visible edge
		JViewport viewPort = (JViewport) getParent();
		Rectangle bounds = viewPort.getViewRect();
		int maxX = bounds.x + bounds.width - 1;
		int startIndex = bounds.x / byteWidth;
		x += startIndex * byteWidth;

		for (int i = startIndex; i < byteSize; i++) {
			// last byte header needs to slightly wider
			int w = byteWidth;
			if (i == (byteSize - 1)) {
				w += BYTE_SEPARATOR_THICKNESS - BIT_SEPARATOR_THICKNESS;
			}
			if (x > maxX) {
				break; // right clip - return early
			}
			paintByte(g, x, y, w, i, baseOffset);
			x += w;
			g.fillRect(x - BYTE_SEPARATOR_THICKNESS, y, BYTE_SEPARATOR_THICKNESS, CELL_HEIGHT); // line after each byte
		}
	}

	private void paintByte(Graphics g, int x, int y, int width, int byteIndex, int baseOffset) {

		Color curColor = g.getColor();

		int offset = byteIndex;
		if (!bigEndian) {
			offset = allocationByteSize - byteIndex - 1;
		}
		offset += baseOffset;

		g.setColor(BYTE_HEADER_COLOR);
		g.fillRect(x, y, width - BYTE_SEPARATOR_THICKNESS, CELL_HEIGHT); // byte fill

		g.setColor(TEXT_COLOR);

		String offsetStr;
		if (showOffsetsInHex) {
			offsetStr = "0x" + Integer.toHexString(offset);
		}
		else {
			offsetStr = Integer.toString(offset);
		}
		FontMetrics fontMetrics = g.getFontMetrics();
		int textY = y + (CELL_HEIGHT + fontMetrics.getMaxAscent() - BYTE_SEPARATOR_THICKNESS) / 2;
		int textX = x + (width - BYTE_SEPARATOR_THICKNESS - fontMetrics.stringWidth(offsetStr)) / 2;
		g.drawString(offsetStr, textX, textY);

		g.setColor(curColor);
	}

	private void paintBits(Graphics2D g, int y) {

		bitFieldAllocation.refresh(false);

		Color curColor = g.getColor();

		BitAttributes[] bitAttributes = bitFieldAllocation.bitAttributes;

		int x = BYTE_SEPARATOR_THICKNESS;

		if (bitAttributes[0] != null && bitAttributes[0].leftEndType == EndBitType.TRUNCATED_END) {
			// adjust left-most line to reflect truncated component 
			x -= BIT_SEPARATOR_THICKNESS; // backup to left line location
			drawTruncationLine(g, x, y, CELL_HEIGHT);
			x += BIT_SEPARATOR_THICKNESS;
		}

		Rectangle dtcRectangle = null;
		DataTypeComponent prevDtc = null;
		BitAttributes prevAttrs = null;

		// Limit rendered bits to those contained within the visible view port
		// of this scrolled component.  

		JViewport viewPort = (JViewport) getParent();
		Rectangle bounds = viewPort.getViewRect();
		int maxX = bounds.x + bounds.width - 1;
		int width = bitAttributes[0].rectangle.width;
		int startIndex = (bounds.x / (bitAttributes[0].rectangle.width)) -
			(8 * bitFieldAllocation.leftChopBytes);
		x += startIndex * width;

		int bitIndex;
		for (bitIndex = startIndex; bitIndex < bitAttributes.length; bitIndex++) {
			BitAttributes attrs = bitAttributes[bitIndex];
			if (x > maxX) {
				break; // right visible edge exceeded - return early
			}
			boolean paintRightLine = bitIndex != (bitAttributes.length - 1);
			attrs.paint(g, prevAttrs, paintRightLine);

			DataTypeComponent dtc = attrs.getDataTypeComponent(false);
			if (prevDtc != null && prevDtc != dtc) {
				paintComponentLabel(g, prevDtc, dtcRectangle);
				prevDtc = null;
			}
			Rectangle visibleBitRect = attrs.rectangle.intersection(bounds);
			if (prevDtc == null) {
				prevDtc = dtc;
				dtcRectangle = visibleBitRect;
			}
			else {
				dtcRectangle.add(visibleBitRect);
			}
			if (attrs.unallocated) {
				paintDit(g, attrs.rectangle);
			}

			prevAttrs = attrs;
			x += width;
		}
		if (prevDtc != null) {
			paintComponentLabel(g, prevDtc, dtcRectangle);
		}

		if (bitIndex == bitAttributes.length && prevAttrs != null &&
			prevAttrs.rightEndType == EndBitType.TRUNCATED_END) {
			x -= BIT_SEPARATOR_THICKNESS; // backup to right line location
			drawTruncationLine(g, x, y, CELL_HEIGHT);
		}

		g.setColor(curColor);
	}

	private void paintDit(Graphics2D g, Rectangle r) {
		Color curColor = g.getColor();

		g.setColor(INTERIOR_LINE_COLOR);
		int x = r.x + (r.width / 2) - 1;
		int y = r.y + (r.height / 2) - 1;
		g.fillRect(x, y, 2, 2);

		g.setColor(curColor);
	}

	private void paintComponentLabel(Graphics g, DataTypeComponent dtc, Rectangle r) {

		if (dtc.getDataType() == DataType.DEFAULT) {
			return;
		}

		String name = dtc.getFieldName();
		if (name == null) {
			return;
		}
		name = " " + name + " ";

		FontMetrics fontMetrics = g.getFontMetrics();
		int strWidth = fontMetrics.stringWidth(name);
		if (strWidth >= r.width) {
			return;
		}

		Color curColor = g.getColor();
		g.setColor(TEXT_COLOR);

		int textY = r.y + (r.height + fontMetrics.getMaxAscent() - BYTE_SEPARATOR_THICKNESS) / 2;
		int textX = r.x + (r.width - BYTE_SEPARATOR_THICKNESS - strWidth) / 2;

		g.drawString(name, textX, textY);

		g.setColor(curColor);
	}

	private static final Stroke DASH = new BasicStroke(1, BasicStroke.CAP_SQUARE,
		BasicStroke.JOIN_MITER, 2, new float[] { 3, 3 }, 0);

	private void drawTruncationLine(Graphics2D g, int x, int y, int height) {

		Color c = g.getColor();
		Stroke s = g.getStroke();

		g.setColor(getBackground()); // draw over black line
		g.setStroke(DASH);
		g.drawLine(x, y, x, y + height - 1);

		g.setColor(c);
		g.setStroke(s);

	}

	/**
	 * <code>BitFieldPlacement</code> provides the ability to translate a 
	 * composite component to a bit-level placement within the allocation
	 * range including the notion of clipped edges when one or both sides 
	 * extend beyond the allocation range.
	 */
	private class BitFieldPlacement {
		int leftBit;
		int rightBit;
		boolean truncateLeft;
		boolean truncateRight;
		boolean zeroBitField;

		BitFieldPlacement(DataTypeComponent component) {
			int startOffset = component.getOffset();
			int offsetAdjBytes = startOffset - allocationByteOffset;
			if (!bigEndian) {
				offsetAdjBytes = allocationByteSize - offsetAdjBytes - component.getLength();
			}
			int leftAdj = 8 * offsetAdjBytes;
			if (component.isBitFieldComponent()) {
				BitFieldDataType bitfield = (BitFieldDataType) component.getDataType();
				int storageSize = 8 * bitfield.getStorageSize();
				rightBit = leftAdj + storageSize - bitfield.getBitOffset() - 1;
				// Use effective bit-size since non-packed uses are only concerned with actual 
				// bits stored (NOTE: this may cause a transition from declared to effective
				// bit-size when editing a bitfield where the these bit-sizes differ).
				int bitSize = bitfield.getBitSize();
				if (bitSize == 0) {
					zeroBitField = true;
					leftBit = rightBit;
				}
				else {
					leftBit = rightBit - bitSize + 1;
				}
			}
			else {
				int componentSize = 8 * component.getLength();
				rightBit = leftAdj + componentSize - 1;
				leftBit = leftAdj;
			}

			// clip to allocation range
			int allocBitSize = 8 * allocationByteSize;
			truncateRight = false;
			if (rightBit >= allocBitSize) {
				truncateRight = true;
				rightBit = allocBitSize - 1;
			}
			truncateLeft = false;
			if (leftBit < 0) {
				truncateLeft = true;
				leftBit = 0;
			}
		}
	}

	/**
	 * <code>BitFieldAllocation</code> provides the bit-level details within the
	 * allocation range including the optional overlay of an edit component
	 * with confict detection.  The bit-level details are defined via 
	 * {@link BitAttributes}.
	 */
	class BitFieldAllocation {

		private final int bitSize;
		private final int bitOffset;

		private boolean hasConflict; // only useable during edit use (see editUseEnabled)

		/**
		 * Reflects actual byte allocation range covered by bitAttributes.
		 * The full allocation is defined by allocationByteSize, where:
		 * <pre>
		 *        {@link #allocationByteSize} = {@link #leftChopBytes} + {@link #allocationBytes} + {@link #rightChopBytes}
		 *        length of {@link #bitAttributes} = 8 * {@link #allocationBytes}
		 * </pre>
		 */
		private Rectangle visibleArea;
		private int allocationBytes;
		private int rightChopBytes;
		private int leftChopBytes;

		/**
		 * Bit attributes array reflects bit layout normalized to big-endian 
		 * layout where left-most allocation bit has array index of 0.  In edit 
		 * mode this array covers the full span of {@link #allocationByteSize}, while in 
		 * non-edit mode the array size is reduced based upon visibility as 
		 * indicated by {@link #leftChopBytes} and {@link #rightChopBytes}.
		 */
		private BitAttributes[] bitAttributes;

		/**
		 * Construct a bitfield allocation with an optional EDIT/ADD component
		 * specified as a bit range.  If editMode is NONE the specified
		 * bit range will be ignored during use.
		 * @param bitSize component bitsize
		 * @param bitOffset component lsb bit offset from lsb of allocation unit.
		 */
		BitFieldAllocation(int bitSize, int bitOffset) {
			int maxBitOffset = (8 * allocationByteSize) - 1;
			if (allocationByteSize <= 0 || bitOffset < 0 || bitSize < 0 ||
				(bitSize + bitOffset - 1) > maxBitOffset) {
				throw new IllegalArgumentException(
					"bitfield not contained within allocation window");
			}
			this.bitSize = bitSize;
			this.bitOffset = bitOffset;
			refresh(true);
		}

		/**
		 * Get the number of bytes contained within the allocationByteSize which
		 * are not visible on the left side.  When edit use is enabled the left
		 * will always be zero regardless of visibility.
		 * @return number of allocation bytes chopped from left
		 */
		private int getLeftByteChop() {
			if (editUseEnabled) {
				return 0;
			}
			if (visibleArea.width == 0) {
				// component not yet contained witin scroll pane
				return allocationByteSize - 1;
			}
			int visibleStart = visibleArea.x;
			return (visibleStart / byteWidth);
		}

		/**
		 * Get the number of bytes contained within the allocationByteSize which
		 * are not visible on the right side.  When edit use is enabled the right
		 * will always be zero regardless of visibility.
		 * @return number of allocation bytes chopped from right
		 */
		private int getRightByteChop() {
			if (editUseEnabled) {
				return 0;
			}
			if (visibleArea.width == 0) {
				// component not yet contained witin scroll pane
				return 0;
			}

			int visibleEnd = visibleArea.x + visibleArea.width - 1;
			int chop = allocationByteSize - ((visibleEnd + byteWidth) / byteWidth);
			return Math.max(0, chop);
		}

		/**
		 * Refresh the computed bitAttributes.  When editUseEnabled is false 
		 * the computed bitAttributes will correspond to the visible portion
		 * of the component.  This method does not handle changes to
		 * {@link #allocationByteSize} which require a new {@link BitFieldAllocation}
		 * instance.
		 * @param force if true a refresh will be forced, otherwise a refresh
		 * will only occur for non-edit use when the visible portion of the component
		 * has changed (e.g., scrolled).
		 */
		private void refresh(boolean force) {
			Rectangle visibleRect = getVisibleRect();
			if (!force && (editUseEnabled || visibleRect.equals(visibleArea))) {
				return; // no change to bitAttributes required
			}
			visibleArea = visibleRect;

			int leftChop = getLeftByteChop();
			int rightChop = getRightByteChop();

			if (!force && (leftChop == leftChopBytes && rightChop == rightChopBytes)) {
				return; // no change to bitAttributes required
			}

			leftChopBytes = leftChop;
			rightChopBytes = rightChop;
			allocationBytes = allocationByteSize - leftChopBytes - rightChopBytes;

			allocateBits();
			layoutBits();
		}

		/**
		 * Generate bit attribute array.  When new or existing component
		 * is active ({@link #editMode} != {@link EditMode#NONE}) the {@link #bitAttributes}
		 * will reflect this as well as any conflict with extsing components.
		 * The {@link #bitAttributes} will also convey placement within the displayed
		 * {@link BitFieldPlacementComponent}.
		 */
		private void allocateBits() {

			if (composite == null) {
				bitAttributes = new BitAttributes[0];
				return;
			}

			bitAttributes = new BitAttributes[8 * allocationBytes];

			if (composite instanceof Structure) {
				allocateStructureMembers((Structure) composite);
			}

			if (editMode != EditMode.NONE) {
				int rightMostBit = (8 * allocationByteSize) - bitOffset - 1;
				if (bitSize == 0) {
					allocateZeroBitField(editComponent, rightMostBit);
				}
				else {
					int leftMostBit = rightMostBit - bitSize + 1;
					allocateBits(editComponent, leftMostBit, rightMostBit, false, false);
				}
			}

			// fill-in unallocated bits
			for (int i = 0; i < bitAttributes.length; i++) {
				if (bitAttributes[i] == null) {
					bitAttributes[i] = new BitAttributes();
				}
			}
		}

		/**
		 * Layout the {@link #bitAttributes} within the {@link BitFieldPlacementComponent}.
		 */
		private void layoutBits() {
			int x = BYTE_SEPARATOR_THICKNESS;
			int y = (2 * BYTE_SEPARATOR_THICKNESS) + CELL_HEIGHT;
			int width = bitWidth + BIT_SEPARATOR_THICKNESS;
			x += 8 * leftChopBytes * width;
			for (BitAttributes attrs : bitAttributes) {
				attrs.layout(x, y, width, CELL_HEIGHT);
				x += width;
			}
		}

		/**
		 * Allocate {@link #bitAttributes} for all structure members which reside
		 * within the byte range covered by {@link #allocationBytes}.
		 * @param struct structure whose component bit attributes should be 
		 *               computed.
		 */
		private void allocateStructureMembers(Structure struct) {

			int offset = allocationByteOffset;
			offset += isBigEndian() ? leftChopBytes : rightChopBytes;

			int allocationEndOffset = offset + allocationBytes - 1;

			int numComponents = struct.getNumComponents();
			DataTypeComponent component = struct.getComponentAt(offset);
			while (component != null) {
				if (component.getOffset() > allocationEndOffset) {
					break;
				}
				if (component.getOrdinal() != editOrdinal) {
					BitFieldPlacement placement = new BitFieldPlacement(component);
					if (placement.zeroBitField) {
						allocateZeroBitField(component, placement.rightBit);
					}
					else {
						allocateBits(component, placement.leftBit, placement.rightBit,
							placement.truncateLeft, placement.truncateRight);
					}
				}
				int nextOrdinal = component.getOrdinal() + 1;
				if (nextOrdinal >= numComponents) {
					break;
				}
				component = struct.getComponent(nextOrdinal);
			}
		}

		/**
		 * Allocate {@link #bitAttributes} for the specified component within
		 * the byte range covered by {@link #allocationBytes}. 
		 * @param dtc composite component
		 * @param leftBit left bit index within the full {@link #allocationByteSize}
		 *                where 0 is the left-most bit index.
		 * @param rightBit right bit index within the full {@link #allocationByteSize}
		 *                 where 0 is the left-most bit index.
		 * @param truncatedLeft true if leftBit has been truncated by the full
		 *                      allocation range
		 * @param truncatedRight true if rightBit has been truncated by the full
		 *                      allocation range
		 */
		private void allocateBits(DataTypeComponent dtc, int leftBit, int rightBit,
				boolean truncatedLeft, boolean truncatedRight) {
			if (truncatedLeft && truncatedRight && leftBit == rightBit) {
				throw new AssertException();
			}

			// adjust bit indexes for missing bitAttributes
			int adjust = 8 * leftChopBytes;
			leftBit -= adjust;
			rightBit -= adjust;

			// compute start and end bit index within allocationBytes which
			// may have been reduced from allocationByteSize based upon visibility.
			int startIndex = Math.max(0, leftBit);
			int endIndex = Math.min((8 * allocationBytes) - 1, rightBit);

			for (int i = startIndex; i <= endIndex; i++) {
				EndBitType leftEndType = EndBitType.NOT_END;
				EndBitType rightEndType = EndBitType.NOT_END;
				if (dtc != null) {
					if (i == leftBit) {
						leftEndType = truncatedLeft ? EndBitType.TRUNCATED_END : EndBitType.END;
					}
					if (i == rightBit) {
						rightEndType = truncatedRight ? EndBitType.TRUNCATED_END : EndBitType.END;
					}
				}
				bitAttributes[i] =
					new BitAttributes(dtc, leftEndType, rightEndType, bitAttributes[i]);
				hasConflict |= bitAttributes[i].hasConflict();
			}
		}

		private void allocateZeroBitField(DataTypeComponent dtc, int bitIndex) {

			// determine placement attribute index within allocationBytes which
			// may have been reduced from allocationByteSize based upon visibility.

			int index = bitIndex - (8 * rightChopBytes);
			if (index >= 0 && index < bitAttributes.length) {
				bitAttributes[index] = new BitAttributes(dtc, bitAttributes[index]);
			}
		}

		public int getBitOffset() {
			return bitOffset;
		}

		public int getBitSize() {
			return bitSize;
		}

	}

	private static enum EditMode {
		NONE, ADD, EDIT;
	}

	private static enum EndBitType {
		NOT_END, END, TRUNCATED_END;
	}

	/**
	 * <code>BitAttributes</code> provide bit attributes which identify the 
	 * associated component, a conflict component and left/right line
	 * types to be displayed.
	 */
	class BitAttributes {

		private final DataTypeComponent dtc;
		private final EndBitType leftEndType;
		private final EndBitType rightEndType;
		private final BitAttributes conflict;

		private boolean zeroBitfield;
		private boolean unallocated;

		private Rectangle rectangle;

		/**
		 * Unallocated bitfield (e.g., bitfield padding)
		 */
		BitAttributes() {
			dtc = null;
			leftEndType = EndBitType.NOT_END;
			rightEndType = EndBitType.NOT_END;
			conflict = null;
			unallocated = true;
		}

		/**
		 * Zero-length bitfield
		 * @param dtc data type component residing within structure or null for edit component
		 * @param conflict conflict or null
		 */
		BitAttributes(DataTypeComponent dtc, BitAttributes conflict) {
			this(dtc, dtc != null ? EndBitType.END : EndBitType.NOT_END,
				dtc != null ? EndBitType.END : EndBitType.NOT_END, conflict);
			zeroBitfield = true;
		}

		/**
		 * Construct bit attributes object
		 * @param dtc data type component residing within structure or null for edit component
		 * @param leftEndType left line type
		 * @param rightEndType right line type
		 * @param conflict conflict or null
		 */
		BitAttributes(DataTypeComponent dtc, EndBitType leftEndType, EndBitType rightEndType,
				BitAttributes conflict) {
			this.dtc = dtc;
			this.leftEndType = leftEndType;
			this.rightEndType = rightEndType;
			this.conflict = conflict;
			if (conflict != null) {
				leftEndType = conflict.leftEndType;
				rightEndType = conflict.rightEndType;
			}
		}

		private boolean isAddBitField() {
			return !unallocated && dtc == null;
		}

		private boolean isEditField() {
			return dtc != null && dtc.getOrdinal() == editOrdinal;
		}

		private boolean hasConflict() {
			return getConflict() != null;
		}

		private DataTypeComponent getConflict() {
			BitAttributes c = conflict;
			while (c != null && c.dtc.isZeroBitFieldComponent()) {
				// TODO: improve conflict detection
				// Zero-length bitfield could be conflict if placement is
				// offcut with another component (currently ignored)
				c = conflict.conflict;
			}
			// NOTE: DEFAULT undefined datatype can be ignored as conflict
			return c != null && c.dtc.getDataType() != DataType.DEFAULT ? c.dtc : null;
		}

		/**
		 * Layout the position of this displayed bit (i.e., Rectangle information)
		 * @param x the  specified X coordinate
		 * @param y the  specified Y coordinate
		 * @param width  the width of the {@code Rectangle}
		 * @param height the height of the {@code Rectangle}
		 */
		void layout(int x, int y, int width, int height) {
			rectangle = new Rectangle(x, y, width, height);
			if (conflict != null) {
				conflict.layout(x, y, width, height);
			}
		}

		private void paint(Graphics g, BitAttributes bitAttrsToLeft, boolean paintRightLine) {
			// bit box
			Color c = getColor();
			g.setColor(c);

			if (zeroBitfield) {

				if (conflict != null) {
					conflict.paint(g, bitAttrsToLeft, paintRightLine);
				}
				if (!bigEndian) {
					bitAttrsToLeft = null;
				}

				c = ACTIVE_BITFIELD_BITS_COLOR;
				Color lineColor = INTERIOR_LINE_COLOR;
				if (dtc != null && dtc != editComponent) {
					c = BITFIELD_COMPONENT_COLOR;
					lineColor = LINE_COLOR;
				}
				// little-endian: place strip on right-side of bit
				// big-endian: place strip on left-side of bit
				int xStrip = bigEndian ? rectangle.x : (rectangle.x + bitWidth - ZERO_BIT_WIDTH);
				int xLine =
					bigEndian ? (xStrip + ZERO_BIT_WIDTH) : (xStrip - BIT_SEPARATOR_THICKNESS);
				g.setColor(c);
				g.fillRect(xStrip, rectangle.y, ZERO_BIT_WIDTH, CELL_HEIGHT);
				g.setColor(lineColor);
				g.fillRect(xLine, rectangle.y, BIT_SEPARATOR_THICKNESS, CELL_HEIGHT);
			}
			else {
				g.fillRect(rectangle.x, rectangle.y, bitWidth, CELL_HEIGHT);
				if (conflict != null && conflict.dtc.isZeroBitFieldComponent()) {
					conflict.paint(g, null, false);
				}
			}

			if (bitAttrsToLeft != null && dtc != null && bitAttrsToLeft.unallocated) {
				// draw left bit line if we know better than the undefined to our left
				g.setColor(LINE_COLOR);
				g.fillRect(rectangle.x - BIT_SEPARATOR_THICKNESS, rectangle.y,
					BIT_SEPARATOR_THICKNESS, CELL_HEIGHT);
			}

			if (paintRightLine) {
				// draw right bit line
				Color lineColor = LINE_COLOR;
				if (rightEndType == EndBitType.NOT_END) {
					lineColor = INTERIOR_LINE_COLOR;
				}
				g.setColor(lineColor);
				g.fillRect(rectangle.x + bitWidth, rectangle.y, BIT_SEPARATOR_THICKNESS,
					CELL_HEIGHT);
			}
		}

		private Color getColor() {
			if (unallocated) {
				return UNDEFINED_BIT_COLOR;
			}
			if (conflict != null && !conflict.unallocated && !conflict.zeroBitfield &&
				conflict.dtc.getDataType() != DataType.DEFAULT) {
				return CONFLICT_BITS_COLOR;
			}
			if (dtc == editComponent) {
				return ACTIVE_BITFIELD_BITS_COLOR; // edit field
			}
			if (dtc.getDataType() == DataType.DEFAULT) {
				return UNDEFINED_BIT_COLOR;
			}
			return dtc.isBitFieldComponent() ? BITFIELD_COMPONENT_COLOR
					: NON_BITFIELD_COMPONENT_COLOR;
		}

		private String getTip() {
			if (unallocated) {
				return "<padding>";
			}
			if (dtc == null) {
				return null;
			}
			String name = dtc.getFieldName();
			return dtc.getDataType().getDisplayName() + (name != null ? (" " + name) : "");
		}

		/**
		 * Get the component of interest at the bit position which corresponds to
		 * this bit attributes object.
		 * @param ignoreActiveComponent if true the edit component will not be returned.
		 * @return component or null
		 */
		DataTypeComponent getDataTypeComponent(boolean ignoreActiveComponent) {
			// Note that this method implementation assumes the edit component
			// will never be a conflict but may contain a conflict component
			// since it is always constructed last.
			if (dtc != null && (dtc.getOrdinal() != editOrdinal || !ignoreActiveComponent)) {
				return dtc;
			}
			if (conflict != null) {
				return conflict.dtc;
			}
			return null;
		}

		Rectangle getRectangle() {
			return rectangle;
		}

	}

}
