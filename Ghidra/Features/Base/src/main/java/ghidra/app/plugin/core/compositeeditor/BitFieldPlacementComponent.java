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
import java.awt.event.MouseEvent;
import java.util.Arrays;
import java.util.HashSet;

import javax.swing.JPanel;
import javax.swing.ToolTipManager;

import ghidra.program.model.data.*;
import ghidra.program.model.data.Composite;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

public class BitFieldPlacementComponent extends JPanel {

	private static final int CELL_HEIGHT = 30;
	private static final int BIT_WIDTH = 10;
	private static final int ZERO_BIT_WIDTH = 3;
	private static final int BIT_SEPARATOR_THICKNESS = 1;
	private static final int BYTE_SEPARATOR_THICKNESS = 2;
	private static final int BYTE_WIDTH = 8 * (BIT_WIDTH + BIT_SEPARATOR_THICKNESS);
	private static final int SCROLLBAR_THICKNESS = 10;
	private static final int MY_HEIGHT = (2 * CELL_HEIGHT) + (3 * BYTE_SEPARATOR_THICKNESS);

	private static final Color TEXT_COLOR = Color.black;
	private static final Color LINE_COLOR = Color.black;
	private static final Color BYTE_HEADER_COLOR = new Color(0xdfdfdf);
	private static final Color UNDEFINED_BIT_COLOR = new Color(0xe8e8e8);
	private static final Color BITFIELD_BITS_COLOR = Color.green;
	private static final Color CONFLICT_BITS_COLOR = Color.yellow;
	private static final Color BITFIELD_COMPONENT_COLOR = new Color(0xcfcfff);
	private static final Color NON_BITFIELD_COMPONENT_COLOR = new Color(0xafafff);
	private static final Color INTERIOR_LINE_COLOR = new Color(0xbfbfbf);

	private final Composite composite;
	private final boolean bigEndian;

	private int allocationOffset;
	private BitFieldAllocation bitFieldAllocation;

	private EditMode editMode = EditMode.NONE;
	private int editOrdinal = -1; // FIXME: improve insert use

	BitFieldPlacementComponent(Composite composite) {
		this.composite = composite;
		bigEndian = composite.getDataOrganization().isBigEndian();
		updatePreferredSize();
		setSize(getPreferredSize());
		setMinimumSize(getPreferredSize());
		ToolTipManager.sharedInstance().registerComponent(this);
	}

	private int getPreferredHeight() {
		return MY_HEIGHT + SCROLLBAR_THICKNESS;
	}

	private int getPreferredWidth() {
		if (bitFieldAllocation == null) {
			return 10;
		}

		int extraLineSpace = BYTE_SEPARATOR_THICKNESS - BIT_SEPARATOR_THICKNESS;
		return (bitFieldAllocation.allocationByteSize * BYTE_WIDTH) + BYTE_SEPARATOR_THICKNESS +
			extraLineSpace;
	}

	public boolean isBigEndian() {
		return bigEndian;
	}

	public BitFieldAllocation getBitFieldAllocation() {
		return bitFieldAllocation;
	}

	int getBitOffset(Point point) {
		int bitWidthWithLine = BIT_WIDTH + BIT_SEPARATOR_THICKNESS;
		int cellIndex = (point.x - BYTE_SEPARATOR_THICKNESS) / bitWidthWithLine;
		return (8 * bitFieldAllocation.allocationByteSize) - cellIndex - 1;
	}

	private void updatePreferredSize() {
		setPreferredSize(new Dimension(getPreferredWidth(), getPreferredHeight()));
		revalidate();
	}

	void refresh(int allocationByteSize, int bitSize, int bitOffset) {
		bitFieldAllocation = new BitFieldAllocation(allocationByteSize, bitSize, bitOffset);
		updatePreferredSize();
		repaint();
	}

	void setAllocationOffset(int allocationOffset) {
		this.allocationOffset = allocationOffset;
		if (bitFieldAllocation != null) {
			bitFieldAllocation.refresh();
			repaint();
		}
	}

	int getAllocationOffset() {
		return allocationOffset;
	}

	void initAdd(int allocationByteSize, int bitSize, int bitOffset) {
		editMode = EditMode.ADD;
		editOrdinal = -1;
		refresh(allocationByteSize, bitSize, bitOffset);
	}

	void init(int allocationByteSize, DataTypeComponent editComponent) {

		if (editComponent == null) {
			editMode = EditMode.NONE;
			editOrdinal = -1;
			refresh(allocationByteSize, 0, 0);
			return;
		}

		// TODO: consider showing a animated hashed-box around original bit boundary
		// of the component being modified

		editMode = EditMode.EDIT;
		editOrdinal = editComponent.getOrdinal();

		BitFieldPlacement placement = new BitFieldPlacement(editComponent, allocationByteSize);
		bitFieldAllocation =
			new BitFieldAllocation(allocationByteSize, placement.rightBit - placement.leftBit + 1,
				(8 * allocationByteSize) - placement.rightBit - 1);
		updatePreferredSize();
		repaint();
	}

	boolean hasApplyConflict() {
		if (composite instanceof Union) {
			return false;
		}
		for (BitAttributes attrs : bitFieldAllocation.bitAttributes) {
			if (attrs.hasConflict() && (attrs.isAddBitField() || attrs.isEditField())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return true if editing or adding a bitfield
	 */
	boolean isEditing() {
		return editMode != EditMode.NONE;
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
			refresh(bitFieldAllocation.allocationByteSize, 0, 0);
		}
	}

	void componentDeleted(int ordinal) {
		if (editMode == EditMode.EDIT) {
			if (ordinal == editOrdinal) {
				// unexpected removal
				editMode = EditMode.ADD;
				editOrdinal = -1;
			}
			else if (ordinal < editOrdinal) {
				--editOrdinal;
			}
		}
		bitFieldAllocation.refresh();
		repaint();
	}

	void applyBitField(DataType baseDataType, String fieldName, boolean deleteConflicts,
			CompositeChangeListener listener) {
		HashSet<Integer> ordinalDeleteSet = new HashSet<>();
		if (editOrdinal >= 0) {
			composite.delete(editOrdinal);
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
			DataTypeComponent dtc;
			if (composite instanceof Union) {
				dtc = composite.insertBitField(ordinal, bitFieldAllocation.allocationByteSize,
					bitFieldAllocation.bitOffset, baseDataType, bitFieldAllocation.bitSize, name,
					null);
			}
			else {
				Structure struct = (Structure) composite;
				dtc = struct.insertBitFieldAt(allocationOffset,
					bitFieldAllocation.allocationByteSize, bitFieldAllocation.bitOffset,
					baseDataType, bitFieldAllocation.bitSize, name, null);
			}
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
			bitFieldAllocation.refresh();
			repaint();
		}
	}

	BitAttributes getBitAttributes(Point p) {
		if (bitFieldAllocation == null) {
			return null;
		}
		for (BitAttributes attrs : bitFieldAllocation.bitAttributes) {
			if (attrs.rectangle != null && attrs.rectangle.contains(p)) {
				return attrs;
			}
		}
		return null;
	}

	@Override
	public String getToolTipText(MouseEvent e) {
		BitAttributes attrs = getBitAttributes(e.getPoint());
		return attrs != null ? attrs.getTip() : null;
	}

	@Override
	public void paintComponent(Graphics g) {

		//super.paintComponent(g);

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

		paintByteHeader(g, BYTE_SEPARATOR_THICKNESS, allocationOffset);
		paintBits((Graphics2D) g, (2 * BYTE_SEPARATOR_THICKNESS) + CELL_HEIGHT);
	}

	private void paintByteHeader(Graphics g, int y, int baseOffset) {
		int byteSize = bitFieldAllocation.allocationByteSize;
		int x = BYTE_SEPARATOR_THICKNESS;
		for (int i = 0; i < byteSize; i++) {
			// last byte header needs to slightly wider
			int w = BYTE_WIDTH;
			if (i == (byteSize - 1)) {
				w += BYTE_SEPARATOR_THICKNESS - BIT_SEPARATOR_THICKNESS;
			}
			paintByte(g, x, y, w, i, baseOffset);
			x += w;
			g.fillRect(x - BYTE_SEPARATOR_THICKNESS, y, BYTE_SEPARATOR_THICKNESS, CELL_HEIGHT); // line after each byte
		}
	}

	private void paintByte(Graphics g, int x, int y, int width, int byteIndex, int baseOffset) {

		Color curColor = g.getColor();
		Font curFont = g.getFont();

		int offset = byteIndex;
		if (!bigEndian) {
			offset = bitFieldAllocation.allocationByteSize - byteIndex - 1;
		}
		offset += baseOffset;

		g.setColor(BYTE_HEADER_COLOR);
		g.fillRect(x, y, width - BYTE_SEPARATOR_THICKNESS, CELL_HEIGHT); // byte fill

		g.setColor(TEXT_COLOR);
		Font textFont = getFont().deriveFont(Font.BOLD);
		g.setFont(textFont);

		String offsetStr = Integer.toString(offset);
		FontMetrics fontMetrics = g.getFontMetrics();
		int textY = y + (CELL_HEIGHT + fontMetrics.getMaxAscent()) / 2;
		int textX = x + (width - BYTE_SEPARATOR_THICKNESS - fontMetrics.stringWidth(offsetStr)) / 2;
		g.drawString(offsetStr, textX, textY);

		g.setColor(curColor);
		g.setFont(curFont);
	}

	private void paintBits(Graphics2D g, int y) {

		Color curColor = g.getColor();

		BitAttributes[] bitAttributes = bitFieldAllocation.bitAttributes;

		int x = BYTE_SEPARATOR_THICKNESS;

		if (bitAttributes[0] != null && bitAttributes[0].leftEndType == EndBitType.TRUNCATED_END) {
			// adjust left-most line to reflect truncated component 
			x -= BIT_SEPARATOR_THICKNESS; // backup to left line location
			drawTruncationLine(g, x, y, CELL_HEIGHT);
			x += BIT_SEPARATOR_THICKNESS;
		}

		BitAttributes prevAttrs = null;

		for (int n = 0; n < bitAttributes.length; n++) {
			BitAttributes attrs = bitAttributes[n];
			boolean paintRightLine = n != (bitAttributes.length - 1);
			attrs.paint(g, prevAttrs, paintRightLine);
			x += attrs.rectangle.width;
			prevAttrs = attrs;
		}

		if (prevAttrs != null && prevAttrs.rightEndType == EndBitType.TRUNCATED_END) {
			x -= BIT_SEPARATOR_THICKNESS; // backup to right line location
			drawTruncationLine(g, x, y, CELL_HEIGHT);
		}

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

	private class BitFieldPlacement {
		int leftBit;
		int rightBit;
		boolean truncateLeft;
		boolean truncateRight;
		boolean zeroBitField;

		BitFieldPlacement(DataTypeComponent component, int allocationByteSize) {
			int startOffset = component.getOffset();
			int offsetAdjBytes = startOffset - allocationOffset;
			if (!bigEndian) {
				offsetAdjBytes = allocationByteSize - offsetAdjBytes - component.getLength();
			}
			int leftAdj = 8 * offsetAdjBytes;
			if (component.isBitFieldComponent()) {
				BitFieldDataType bitfield = (BitFieldDataType) component.getDataType();
				int storageSize = 8 * bitfield.getStorageSize();
				rightBit = leftAdj + storageSize - bitfield.getBitOffset() - 1;
				// Use effective bit-size since unaligned uses are only concerned with actual 
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

//			System.out.println(component.toString() + " >>> " + leftBit + " - " + rightBit +
//				"  oa: " + offsetAdjBytes);

			// clip to allocation region
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

	class BitFieldAllocation {

		private final int allocationByteSize;
		private final int bitSize;
		private final int bitOffset;
		private boolean hasConflict;

		// bit layout normalized to big-endian layout
		// left-most allocation msb has array index of 0 
		private BitAttributes[] bitAttributes;

		BitFieldAllocation(int allocationByteSize, int bitSize, int bitOffset) {
			if (allocationByteSize <= 0 || (bitSize + bitOffset) > (8 * allocationByteSize)) {
				throw new IllegalArgumentException("allocation size too small");
			}
			this.allocationByteSize = allocationByteSize;
			this.bitSize = bitSize;
			this.bitOffset = bitOffset;
			refresh();
		}

		private void refresh() {
			allocateBits();
			layoutBits();
		}

		private void allocateBits() {
			bitAttributes = new BitAttributes[8 * allocationByteSize];

			if (composite instanceof Structure) {
				allocateStructureMembers((Structure) composite);
			}

			if (editMode != EditMode.NONE) {
				int rightMostBit = bitAttributes.length - bitOffset - 1;
				if (bitSize == 0) {
					allocateZeroBitField(null, rightMostBit);
				}
				else {
					int leftMostBit = rightMostBit - bitSize + 1;
					allocateBits(null, leftMostBit, rightMostBit, false, false);
				}
			}

			// fill-in unallocated bits
			for (int i = 0; i < bitAttributes.length; i++) {
				if (bitAttributes[i] == null) {
					bitAttributes[i] = new BitAttributes();
				}
			}
		}

		private void layoutBits() {
			int x = BYTE_SEPARATOR_THICKNESS;
			int y = (2 * BYTE_SEPARATOR_THICKNESS) + CELL_HEIGHT;
			int width = BIT_WIDTH + BIT_SEPARATOR_THICKNESS;
			for (BitAttributes attrs : bitAttributes) {
				attrs.layout(x, y, width, CELL_HEIGHT);
				x += width;
			}
		}

		private void allocateStructureMembers(Structure struct) {

			int allocationEndOffset = allocationOffset + allocationByteSize - 1;

			for (DataTypeComponent component : struct.getDefinedComponents()) {
				if (component.getOrdinal() == editOrdinal) {
					continue;
				}
				int startOffset = component.getOffset();
				int endOffset = component.getEndOffset();
				if (endOffset < allocationOffset) {
					continue;
				}
				if (startOffset > allocationEndOffset) {
					continue;
				}
				BitFieldPlacement placement = new BitFieldPlacement(component, allocationByteSize);
				if (placement.zeroBitField) {
					allocateZeroBitField(component, placement.rightBit);
				}
				else {
					allocateBits(component, placement.leftBit, placement.rightBit,
						placement.truncateLeft, placement.truncateRight);
				}
			}
		}

		private void allocateBits(DataTypeComponent dtc, int leftBit, int rightBit,
				boolean truncatedLeft, boolean truncatedRight) {
			if (truncatedLeft && truncatedRight && leftBit == rightBit) {
				throw new AssertException();
			}
			int startIndex = Math.max(0, leftBit);
			int endIndex = Math.min(bitAttributes.length - 1, rightBit);
			for (int i = startIndex; i <= endIndex; i++) {
				EndBitType leftEndType = EndBitType.NOT_END;
				EndBitType rightEndType = EndBitType.NOT_END;
				if (dtc != null) {
					if (i == leftBit) {
						leftEndType = truncatedLeft ? EndBitType.TRUNCATED_END : EndBitType.END;
					}
					if (i == rightBit) {
						rightEndType = truncatedLeft ? EndBitType.TRUNCATED_END : EndBitType.END;
					}
				}
				bitAttributes[i] =
					new BitAttributes(dtc, leftEndType, rightEndType, bitAttributes[i]);
				hasConflict |= bitAttributes[i].hasConflict();
			}
		}

		private void allocateZeroBitField(DataTypeComponent dtc, int bitIndex) {
			bitAttributes[bitIndex] = new BitAttributes(dtc, bitAttributes[bitIndex]);
		}

		public int getAllocationByteSize() {
			return allocationByteSize;
		}

		public int getBitOffset() {
			return bitOffset;
		}

		public int getBitSize() {
			return bitSize;
		}

	}

	static enum EditMode {
		NONE, ADD, EDIT;
	}

	static enum EndBitType {
		NOT_END, END, TRUNCATED_END;
	}

	class BitAttributes {

		private final DataTypeComponent dtc;
		private final EndBitType leftEndType;
		private final EndBitType rightEndType;
		private final BitAttributes conflict;

		private boolean zeroBitfield;
		private boolean unallocated;

		Rectangle rectangle;

		/**
		 * Unallocated bitfield
		 * @param dtc
		 * @param conflict
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
		 * @param dtc
		 * @param conflict
		 */
		BitAttributes(DataTypeComponent dtc, BitAttributes conflict) {
			this(dtc, dtc != null ? EndBitType.END : EndBitType.NOT_END,
				dtc != null ? EndBitType.END : EndBitType.NOT_END, conflict);
			zeroBitfield = true;
		}

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

		boolean isAddBitField() {
			return !unallocated && dtc == null;
		}

		boolean isEditField() {
			return dtc != null && dtc.getOrdinal() == editOrdinal;
		}

		boolean hasConflict() {
			return getConflict() != null;
		}

		public DataTypeComponent getConflict() {
			BitAttributes c = conflict;
			while (c != null && c.dtc.isZeroBitFieldComponent()) {
				c = conflict.conflict;
			}
			return c != null ? c.dtc : null;
		}

		void layout(int x, int y, int width, int height) {
			rectangle = new Rectangle(x, y, width, height);
		}

		void paint(Graphics g, BitAttributes bitAttrsToLeft, boolean paintRightLine) {
			// bit box
			Color c = getColor();
			g.setColor(c);
			g.fillRect(rectangle.x, rectangle.y, BIT_WIDTH, CELL_HEIGHT);

			if (zeroBitfield ||
				(dtc != null && conflict != null && conflict.dtc.isZeroBitFieldComponent())) {
				c = BITFIELD_BITS_COLOR;
				Color lineColor = INTERIOR_LINE_COLOR;
				if (dtc != null) {
					c = BITFIELD_COMPONENT_COLOR;
					lineColor = LINE_COLOR;
				}
				// little-endian: place strip on right-side of bit
				// big-endian: place strip on left-side of bit
				int xStrip = bigEndian ? rectangle.x : (rectangle.x + BIT_WIDTH - ZERO_BIT_WIDTH);
				int xLine =
					bigEndian ? (xStrip + ZERO_BIT_WIDTH) : (xStrip - BIT_SEPARATOR_THICKNESS);
				g.setColor(c);
				g.fillRect(xStrip, rectangle.y, ZERO_BIT_WIDTH, CELL_HEIGHT);
				g.setColor(lineColor);
				g.fillRect(xLine, rectangle.y, BIT_SEPARATOR_THICKNESS, CELL_HEIGHT);
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
				g.fillRect(rectangle.x + BIT_WIDTH, rectangle.y, BIT_SEPARATOR_THICKNESS,
					CELL_HEIGHT);
			}
		}

		Color getColor() {
			// zero-length stripe will be added later and
			// should treated as a conflict
			if (unallocated) {
				return UNDEFINED_BIT_COLOR;
			}
			if (conflict != null && !conflict.unallocated) {
				if (zeroBitfield) {
					return conflict.getColor();
				}
				if (!conflict.dtc.isZeroBitFieldComponent()) {
					return CONFLICT_BITS_COLOR;
				}
			}
			if (zeroBitfield) {
				return UNDEFINED_BIT_COLOR;
			}
			if (dtc == null) {
				return BITFIELD_BITS_COLOR; // edit field
			}
			return dtc.isBitFieldComponent() ? BITFIELD_COMPONENT_COLOR
					: NON_BITFIELD_COMPONENT_COLOR;
		}

		String getTip() {
			if (dtc == null) {
				return null;
			}
			String name = dtc.getFieldName();
			return dtc.getDataType().getDisplayName() +
				(name != null ? (" " + dtc.getFieldName()) : "");
		}

		DataTypeComponent getDataTypeComponent(boolean ignoreEditComponent) {
			if (dtc != null && (dtc.getOrdinal() != editOrdinal || !ignoreEditComponent)) {
				return dtc;
			}
			if (conflict != null) {
				return conflict.dtc;
			}
			return null;
		}

	}

}
