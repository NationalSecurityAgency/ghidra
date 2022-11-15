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
package ghidra.app.util.viewer.format;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.border.Border;

import docking.widgets.label.GDLabel;
import generic.theme.GColor;
import generic.theme.Gui;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import help.Help;
import help.HelpService;

/**
 * Class manage a header for the FieldViewer.
 */
public class FieldHeaderComp extends JPanel {
	private static final String FONT_ID = "font.listing.header";

	private enum CursorState {
		NOWHERE, NEAR_EDGE, OVER_FIELD
	}

	private static final int FUDGE = 5;
	private static final int MIN_FIELD_SIZE = 10;

	private static final int DEFAULT_SNAP_SIZE = 10;

	private static final Color ACTIVE_FIELD_BG_COLOR =
		new GColor("color.bg.listing.header.active.field");
	private static final Color ACTIVE_FIELD_FG_COLOR =
		new GColor("color.fg.listing.header.active.field");

	private FieldFormatModel model;
	private JLabel label;
	private int rowHeight;
	private CursorState state;
	private int curRow;
	private int curCol;
	private int edgeCol;
	private int edgeColSize;
	private int anchorX;
	private int anchorY;
	private int snapSize = DEFAULT_SNAP_SIZE;
	private Color defaultButtonBgColor;
	private Color defaultButtonFgColor;

	private boolean editInProgress;
	private MovingField moving;

	private CellRendererPane renderPane; // used to render the field headers
	private Cursor defaultCursor = Cursor.getDefaultCursor();
	private Cursor resizeCursor = Cursor.getPredefinedCursor(Cursor.E_RESIZE_CURSOR);
	private FieldHeader headerPanel;

	/**
	 * Constructs a new FieldHeader for the given model.
	 * @param headerPanel the headerPanel containing this component.
	 * @param modelNumber the model number for this component.
	 */
	public FieldHeaderComp(FieldHeader headerPanel, int modelNumber) {
		FormatManager formatMgr = headerPanel.getFormatManager();
		this.model = formatMgr.getModel(modelNumber);
		this.headerPanel = headerPanel;
		Border border1 = BorderFactory.createRaisedBevelBorder();
		Border border2 = BorderFactory.createEmptyBorder(0, 0, 1, 1);

		label = new GDLabel("Test");
		label.setOpaque(true);
		label.setHorizontalAlignment(SwingConstants.CENTER);
		defaultButtonBgColor = label.getBackground();
		defaultButtonFgColor = label.getForeground();
		label.setBorder(BorderFactory.createCompoundBorder(border2, border1));
		label.setFont(Gui.getFont(FONT_ID));
		Dimension d = label.getPreferredSize();
		rowHeight = d.height;
		this.setMinimumSize(new Dimension(0, 2 * rowHeight));
		renderPane = new CellRendererPane();

		setLayout(new FlowLayout(FlowLayout.LEFT, 0, 0));

		HelpService help = Help.getHelpService();
		help.registerHelp(this, new HelpLocation("CodeBrowserPlugin", "Field_Formatter"));

		// process mouse motion events
		setBorder(BorderFactory.createRaisedBevelBorder());
		addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				FieldHeaderComp.this.headerPanel.requestFocus();
				if ((e.getModifiersEx() == InputEvent.BUTTON1_DOWN_MASK)) {
					pressed(e.getX(), e.getY());
				}
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				if ((e.getModifiersEx() == 0)) {
					// Only perform the release when no modifiers are present.  This prevents other
					// button press combinations from triggering the release.
					released(e.getX(), e.getY());
				}
			}
		});

		addMouseMotionListener(new MouseMotionAdapter() {
			@Override
			public void mouseMoved(MouseEvent e) {
				setCursor(e.getX(), e.getY());
			}

			@Override
			public void mouseDragged(MouseEvent e) {
				if ((e.getModifiersEx() == InputEvent.BUTTON1_DOWN_MASK)) {
					dragged(e.getX(), e.getY());
				}
			}
		});
	}

	/**
	 * Returns the currently displayed model.
	 * @return the currently displayed model.
	 */
	public FieldFormatModel getModel() {
		return model;
	}

	/**
	 * Called when the model's layout changes.
	 */
	public void update() {
		invalidate();
		repaint();
	}

	/**
	 * Sets the cursor shape that appropriate for the given location.  If the location
	 * is near a boundary, then the cursor will change to a RESIZE shape, otherwise
	 * it will be the default cursor.
	 */
	private void setCursor(int x, int y) {
		int row = y / rowHeight;
		curRow = -1;
		curCol = -1;
		state = CursorState.NOWHERE;
		if (row < model.getNumRows()) {
			curRow = row;
			int startX = 0;
			FieldFactory[] fields = model.getFactorys(row);
			for (int col = 0; col < fields.length; col++) {
				int width = fields[col].getWidth();
				if (x < startX + width) {
					state = CursorState.OVER_FIELD;
					curCol = col;
					if ((col > 0) && (x < startX + FUDGE)) {
						state = CursorState.NEAR_EDGE;
						edgeCol = col - 1;
					}
					else if (x > startX + width - FUDGE) {
						state = CursorState.NEAR_EDGE;
						edgeCol = col;
					}
					break;
				}
				startX += width;
			}
		}

		switch (state) {
			case OVER_FIELD:
				setCursor(defaultCursor);
				break;
			case NEAR_EDGE:
				setCursor(resizeCursor);
				break;
			default:
				setCursor(defaultCursor);
				break;

		}
	}

	private void pressed(int x, int y) {
		editInProgress = true;
		headerPanel.setTabLock(true);
		setCursor(x, y);
		anchorX = x;
		anchorY = y;
		switch (state) {
			case NEAR_EDGE:
				FieldFactory[] fields = model.getFactorys(curRow);
				edgeColSize = fields[edgeCol].getWidth();
				break;
			case OVER_FIELD:
				moving = new MovingField(curRow, curCol);
				break;
			default:
		}
	}

	private void released(int x, int y) {
		if (!editInProgress) {
			return;
		}

		editInProgress = false;
		int deltaX = x - anchorX;
		int deltaY = y - anchorY;

		switch (state) {
			case NEAR_EDGE:
				resize(deltaX);
				invalidate();
				update();
				break;
			case OVER_FIELD:
				moving.moveFloating(deltaX, deltaY);
				moving.move();
				moving = null;
				invalidate();
				getParent().getParent().validate();
				update();
				break;
			default:
		}
		Swing.runLater(() -> headerPanel.setTabLock(false));
	}

	private void dragged(int x, int y) {
		int deltaX = x - anchorX;
		int deltaY = y - anchorY;
		anchorX = x;
		anchorY = y;

		switch (state) {
			case NEAR_EDGE:
				resize(deltaX);
				break;
			case OVER_FIELD:
				moving.moveFloating(deltaX, deltaY);
				repaint();
				break;
			default:
		}
	}

	private void resize(int deltaX) {
		int row = curRow;
		int col = edgeCol;
		edgeColSize += deltaX;
		int newWidth = edgeColSize;
		if (newWidth < MIN_FIELD_SIZE) {
			newWidth = MIN_FIELD_SIZE;
		}
		newWidth = ((newWidth + snapSize / 2) / snapSize) * snapSize;
		FieldFactory[] fields = model.getFactorys(row);
		fields[col].setWidth(newWidth);
		model.updateRow(row);
		repaint();
	}

	/**
	 * Returns the row in the model that the point is over.
	 * @param p the point for which to find its corresponding row
	 * @return the row
	 */
	public int getRow(Point p) {
		if (p.y < 0) {
			return 0;
		}
		int row = p.y / rowHeight;
		if (row >= model.getNumRows()) {
			row = model.getNumRows();
		}
		return row;
	}

	/**
	 * Returns the index of the field on the given row containing the give x position.
	 * @param row the row on which to find the index of the field containing the x coordinate.
	 * @param x the horizontal coordinate (in pixels) 
	 * @return the column
	 */
	public int getCol(int row, int x) {
		if (x < 0) {
			return 0;
		}
		if (row < 0) {
			row = 0;
		}
		else if (row >= model.getNumRows()) {
			return 0;
		}

		int xpos = 0;
		FieldFactory[] fields = model.getFactorys(row);
		for (int i = 0; i < fields.length; i++) {
			xpos += fields[i].getWidth();
			if (x < xpos) {
				return i;
			}
		}
		return fields.length;
	}

	@Override
	public void paint(Graphics g) {

		g.setColor(defaultButtonBgColor);
		int nRows = model.getNumRows();
		Dimension dim = getSize();
		g.fillRect(0, 0, dim.width, dim.height);
		paintBorder(g);
		FieldFactory selectedFactory = headerPanel.getSelectedFieldFactory();
		for (int i = 0; i < nRows; i++) {
			FieldFactory[] factorys = model.getFactorys(i);
			int nfields = factorys.length;
			int startX = 0;
			for (int j = 0; j < nfields; j++) {
				String name = factorys[j].getFieldText();
				int startY = i * rowHeight;
				int width = factorys[j].getWidth();
				int height = rowHeight;
				label.setText(name);
				label.setEnabled(factorys[j].isEnabled());
				if (factorys[j] == selectedFactory) {
					label.setBackground(ACTIVE_FIELD_BG_COLOR);
					label.setForeground(ACTIVE_FIELD_FG_COLOR);
				}
				else {
					label.setBackground(defaultButtonBgColor);
					label.setForeground(defaultButtonFgColor);
				}

				renderPane.paintComponent(g, label, this, startX, startY, width, height, true);

				startX += width;
			}
		}
		if (moving != null) {
			label.setText(moving.name);
			renderPane.paintComponent(g, label, this, moving.floatingX, moving.floatingY,
				moving.width, rowHeight, true);
		}

	}

	@Override
	public Dimension getPreferredSize() {
		FormatManager formatManager = model.getFormatManager();
		int height = formatManager.getMaxRowCount() * rowHeight + 1;
		return new Dimension(formatManager.getMaxWidth(), height);
	}

	@Override
	public void setBounds(int x, int y, int width, int height) {
		super.setBounds(x, y, width, height);
	}

	/**
	 * Returns a FieldHeaderLocation for the given point
	 * @param p the point to get a location for
	 * @return the location
	 */
	public FieldHeaderLocation getFieldHeaderLocation(Point p) {
		int row = getRow(p);
		if (row >= model.getNumRows()) {
			row = model.getNumRows() - 1;
		}

		int col = getCol(row, p.x);
		FieldFactory factory = null;
		if (row < model.getNumRows() && col < model.getNumFactorys(row)) {
			factory = model.getFactorys(row)[col];
		}
		return new FieldHeaderLocation(model, factory, row, col);

	}

	@Override
	public String toString() {
		return model.getName();
	}

	/**
	 * Class for keeping track of a field that is the process of being dragged.
	 */
	class MovingField {
		int baseRow;
		int baseCol;

		String name;
		int floatingX;
		int floatingY;
		int width;
		int x;
		int y;

		int widthRightField;
		int widthLeftField;

		MovingField(int row, int col) {
			baseRow = row;
			baseCol = col;
			FieldFactory factory = model.getFactorys(row)[col];
			name = factory.getFieldName();
			reset();
			floatingX = x;
			floatingY = y;
			width = factory.getWidth();

		}

		void moveFloating(int deltaX, int deltaY) {
			floatingX += deltaX;
			floatingY += deltaY;
		}

		void move() {
			if (((floatingY - y) > rowHeight / 2) && baseRow < 11) {
				// move down
				if (baseRow + 1 == model.getNumRows()) {
					model.addRow(baseRow + 1);
				}
				model.moveFactory(baseRow, baseCol, baseRow + 1, 0);
				baseRow++;
				baseCol = 0;
				reset();
				move();
			}
			else if (((y - floatingY) > rowHeight / 2) && (baseRow > 0)) {
				// move up
				model.moveFactory(baseRow, baseCol, baseRow - 1, 0);
				if (baseRow == model.getNumRows() - 1) {
					if (model.getNumFactorys(baseRow) == 0) {
						model.removeRow(baseRow);
					}
				}
				baseRow--;
				baseCol = 0;
				reset();
				move();
			}
			else { // check if we need to move left or right on this row
				int diff = floatingX - x;
				if ((diff >= 0) && (widthRightField >= 0) && (diff > widthRightField / 2)) {
					// move right
					model.moveFactory(baseRow, baseCol, baseRow, baseCol + 1);
					baseCol += 1;
					reset();
					move();
				}
				else if ((widthLeftField >= 0) && (-diff > widthLeftField / 2)) {
					// move left
					model.moveFactory(baseRow, baseCol, baseRow, baseCol - 1);
					baseCol -= 1;
					reset();
					move();
				}
			}

		}

		/**
		 * Resets relative position state when the base field is moved.
		 */
		private void reset() {
			x = getStart();
			y = baseRow * rowHeight;

			widthLeftField = -1;
			widthRightField = -1;
			if (baseCol > 0) {
				widthLeftField = model.getFactorys(baseRow)[baseCol - 1].getWidth();
			}
			if (baseCol < model.getFactorys(baseRow).length - 1) {
				widthRightField = model.getFactorys(baseRow)[baseCol + 1].getWidth();
			}

		}

		private int getStart() {
			int start = 0;
			FieldFactory[] factorys = model.getFactorys(baseRow);
			for (int i = 0; i < baseCol; i++) {
				start += factorys[i].getWidth();
			}
			return start;
		}

	}
}
