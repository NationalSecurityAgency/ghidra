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
package ghidra.app.plugin.core.bento;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.*;

import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors;

public class BentoPanel extends JPanel implements MouseListener, MouseMotionListener {
	private static final long serialVersionUID = 1L;

	private static final Color ARROW_COLOR =
		new GColor("color.debugger.plugin.plugin.memview.arrow");

	private BentoProvider provider;
	private List<BentoBox> boxList = new ArrayList<>();

	private int pressedX;
	private int pressedY;
	private int pressedHZ;
	private int pressedVT;
	private boolean enableDrag = false;
	private boolean ctrlPressed = false;
	private int barWidth = 1000;
	private int barHeight = 500;

	private Rectangle currentRectangle = null;

	private List<BentoBox> blist = Collections.emptyList();
	private Map<String, BentoBox> bmap = new HashMap<>();

	private BentoAxialData dataX;
	private BentoAxialData dataY;

	public BentoPanel(BentoProvider provider) {
		this.provider = provider;
		dataX = new BentoAxialData(provider, 0);
		dataY = new BentoAxialData(provider, 1);
		setPreferredSize(new Dimension(barWidth, barHeight));
		setSize(getPreferredSize());
		setBorder(BorderFactory.createLineBorder(Colors.BORDER, 1));
		setFocusable(true);

		addMouseListener(this);
		addMouseMotionListener(this);
		ToolTipManager.sharedInstance().registerComponent(this);

		// This panel takes focus since it is a custom widget. Focusable components need to
		// have their accessible name set.
		String viewName = "Box View";
		setName(viewName);
		getAccessibleContext().setAccessibleName(viewName);
	}

	@Override
	public Dimension getPreferredSize() {
		BentoPixelMap xMap = dataX.getMap();
		BentoPixelMap yMap = dataY.getMap();
		int h = yMap != null ? (int) (yMap.getSize()) : 500;
		int w = xMap != null ? (int) (xMap.getSize()) : 500;
		return new Dimension(w, h);
	}

	@Override
	public void paintComponent(Graphics g) {
		super.paintComponent(g);
		g.setColor(getBackground());
		Rectangle clip = g.getClipBounds();
		g.fillRect(clip.x, clip.y, clip.width, clip.height);

		//If the width has changed, force a refresh
		int height = getHeight();
		int width = getWidth();
		if (clip.height > height) {
			refresh();
			return;
		}

		g.fillRect(0, 0, width, height);

		for (BentoBox box : boxList) {
			box.render(g, dataX.getIndex(), dataY.getIndex());
		}

		//Draw the current location arrow
		if (dataY.getCurrentPixel() >= 0) {
			drawArrow(g);
		}
		if (currentRectangle != null) {
			drawFrame(g);
		}
	}

	private static final int LOCATION_BASE_WIDTH = 1;
	private static final int LOCATION_BASE_HEIGHT = 6;
	private static final int LOCATION_ARROW_WIDTH = 3;
	private static final int LOCATION_ARROW_HEIGHT = 9;
	private static final int[] locXs = { 0, -LOCATION_BASE_WIDTH, -LOCATION_BASE_WIDTH,
		-LOCATION_ARROW_WIDTH, 0, LOCATION_ARROW_WIDTH, LOCATION_BASE_WIDTH, LOCATION_BASE_WIDTH };
	private static final int[] locYs = { 0, 0, LOCATION_BASE_HEIGHT, LOCATION_BASE_HEIGHT,
		LOCATION_ARROW_HEIGHT, LOCATION_BASE_HEIGHT, LOCATION_BASE_HEIGHT, 0 };

	private void drawArrow(Graphics g) {
		Graphics2D g2 = (Graphics2D) g.create();
		try {
			int curY = dataY.getCurrentPixel();
			int curX = dataX.getCurrentPixel();
			g2.translate(0, -LOCATION_ARROW_HEIGHT);
			g.translate(curX, curY);

			g.setColor(ARROW_COLOR);
			g.fillPolygon(locXs, locYs, locXs.length);

			g.translate(-curX, -curY);
			g2.translate(0, LOCATION_ARROW_HEIGHT);
		}
		finally {
			g2.dispose();
		}
	}

	private void drawFrame(Graphics g) {
		int x = currentRectangle.x;
		int y = currentRectangle.y;
		int w = currentRectangle.width;
		int h = currentRectangle.height;
		g.setColor(ARROW_COLOR);
		g.fillRect(x - 1, y - 1, 1, h + 2);
		g.fillRect(x - 1, y - 1, w + 2, 1);
		g.fillRect(x + w + 1, y - 1, 1, h + 2);
		g.fillRect(x - 1, y + h + 1, w + 2, 1);
	}

	void initViews() {
		int szX = dataX.initViews();
		int szY = dataY.initViews();
		setSize(new Dimension(szX, szY));
	}

	public void refresh() {
		dataX.refresh();
		dataY.refresh();
		updateBoxes();
	}

	void updateBoxes() {
		if (!this.isShowing()) {
			return;
		}

		Collection<BentoBox> boxes = getBoxes();
		if (boxes == null) {
			return;
		}
		List<BentoBox> updatedList = new ArrayList<>();
		BentoPixelMap xMap = dataX.getMap();
		BentoPixelMap yMap = dataY.getMap();

		int boundX = getWidth() - 1;
		int boundY = getHeight() - 1;

		for (BentoBox box : boxes) {
			if (box == null) {
				continue;
			}

			box.getObj(dataX.getIndex()).getMappedObject().setBounds(xMap, boundX);
			box.getObj(dataY.getIndex()).getMappedObject().setBounds(yMap, boundY);

			updatedList.add(box);
		}

		this.boxList = updatedList;
		repaint();
		//repaint(0, 0, getWidth(), getHeight());
	}

	@Override
	public void mousePressed(MouseEvent e) {
		requestFocus();  // COMPONENT

		ctrlPressed = false;
		currentRectangle = null;

		if (e.getButton() == MouseEvent.BUTTON1) {
			enableDrag = true;
			pressedHZ = e.getX();
			pressedVT = e.getY();
			pressedX = pressedHZ;
			pressedY = pressedVT;
			dataX.setCurrentPixel(pressedX);
			dataY.setCurrentPixel(pressedY);
			provider.selectTableEntry(getBoxesAt(pressedX, pressedY));
			provider.refresh();
		}

		if (e.getButton() == MouseEvent.BUTTON3) {
			ctrlPressed = true;
			enableDrag = true;
			pressedHZ = e.getX();
			pressedVT = e.getY();
		}
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		enableDrag = false;
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		if (e.getClickCount() == 2) {
			provider.navigateToSelectedObject();
		}
		enableDrag = false;
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		// Nothing to do
	}

	@Override
	public void mouseExited(MouseEvent e) {
		// Nothing to do
	}

	@Override
	public void mouseDragged(MouseEvent e) {
		if (enableDrag) {
			if (!ctrlPressed) {
				provider.goTo(pressedHZ - e.getX(), pressedVT - e.getY());
			}
			else {
				int x = Math.min(pressedHZ, e.getX());
				int y = Math.min(pressedVT, e.getY());
				int w = Math.abs(e.getX() - pressedHZ);
				int h = Math.abs(e.getY() - pressedVT);

				currentRectangle = new Rectangle(x, y, w, h);
				provider.selectTableEntry(getBoxesIn(currentRectangle));
				provider.refresh();
			}
		}
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		// Nothing to do
	}

	public void setSelection(Set<BentoBox> boxes) {
		for (BentoBox box : boxes) {
			dataX.setCurrentPixel(box.getObj(0).getMappedObject().getPixelStart());
			dataY.setCurrentPixel(box.getObj(1).getMappedObject().getPixelStart());
			refresh();
		}
	}

	public String getTitleAnnotation() {
		String xval = dataX.getTagForPos(null);
		String yval = dataY.getTagForPos(null);
		String vals = xval + ":" + yval;
		return "curpos=[" + vals + "]";
	}

	public Set<BentoBox> getBoxesAt(int atX, int atY) {
		Rectangle posRect = new Rectangle(atX, atY, 1, 1);
		return getBoxesIn(posRect);
	}

	public Set<BentoBox> getBoxesIn(Rectangle r) {
		int startX = (int) dataX.getPos(r.x);
		int startY = (int) dataY.getPos(r.y);
		int stopX = (int) dataX.getPos(r.x + r.width);
		int stopY = (int) dataY.getPos(r.y + r.height);

		Rectangle posRect = new Rectangle(startX, startY,
			stopX - startX + 1, stopY - startY + 1);

		Set<BentoBox> matches = new HashSet<>();
		for (BentoBox box : boxList) {
			Rectangle boxRect = box.getRectangle(dataX.getIndex(), dataY.getIndex());
			if (posRect.intersects(boxRect)) {
				matches.add(box);
			}
		}
		return matches;
	}

	@Override
	public String getToolTipText(MouseEvent e) {
		BentoPixelMap xMap = dataX.getMap();
		BentoPixelMap yMap = dataY.getMap();
		if (yMap == null || xMap == null) {
			return e.getX() + ":" + e.getY();
		}

		int pixX = e.getX();
		long x = dataX.getPos(pixX);
		int pixY = e.getY();
		long y = dataY.getPos(pixY);
		String xval = dataX.getTagForPos(x);
		String yval = dataY.getTagForPos(y);
		Set<BentoBox> boxes = getBoxesAt(pixX, pixY);

		StringBuilder sb = new StringBuilder(yval);
		sb.append(" [");
		boolean first = true;
		for (BentoBox box : boxes) {
			if (box.getId() == null) {
				continue;
			}
			if (!first) {
				sb.append(",");
			}
			sb.append(box.getId());
			first = false;
		}
		sb.append("]");
		yval = sb.toString();

		String colon = xval.equals("") && yval.equals("") ? "" : " : ";
		return xval + colon + yval;
	}

	private void parseBoxes(Collection<BentoBox> boxes) {
		if (!boxes.isEmpty()) {
			double d = Math.log(getWidth() / boxes.size()) / Math.log(2.0);
			int escapeCounter = 0;
			while (dataX.getZoom() < d && escapeCounter < 50) {
				provider.changeZoom(0, 1);
				provider.changeZoom(1, 1);
				escapeCounter++;
			}
		}
		dataX.parseBoxes(boxes);
		dataY.parseBoxes(boxes);
		refresh();
	}

	public List<BentoBox> getBoxes() {
		return blist;
	}

	public void setBoxes(List<BentoBox> boxes) {
		this.blist = boxes;
		for (BentoBox b : boxes) {
			if (b.getId() != null) {
				bmap.put(b.getId(), b);
			}
		}
		parseBoxes(blist);
	}

	public void addBoxes(List<BentoBox> boxes) {
		if (blist == null) {
			blist = new ArrayList<>();
		}
		for (BentoBox b : boxes) {
			if (bmap.containsKey(b.getId())) {
				BentoBox box = bmap.get(b.getId());
				blist.remove(box);
			}
			blist.add(b);
			bmap.put(b.getId(), b);
		}
		parseBoxes(blist);
	}

	public void reset() {
		blist = new ArrayList<>();
		bmap.clear();
		parseBoxes(blist);
	}

	protected BentoRadix getRadix(int index) {
		if (boxList == null || boxList.isEmpty()) {
			return BentoRadix.DEFAULT;
		}
		return provider.getRadix(index);
	}

	public void scaleCurrentPixel(int index, double changeAmount) {
		switch (index) {
			case 0 -> {
				dataX.scaleCurrentPixel(changeAmount);
			}
			case 1 -> {
				dataY.scaleCurrentPixel(changeAmount);
			}
		}
	}

	public double getZoom(int index) {
		return switch (index) {
			case 0 -> dataX.getZoom();
			case 1 -> dataY.getZoom();
			default -> throw new IllegalArgumentException("Unexpected zoom index");
		};
	}

	public void setIndex(boolean x, int colIndex) {
		if (x) {
			dataX.setIndex(colIndex);
		}
		else {
			dataY.setIndex(colIndex);
		}
	}

	public int getIndex(boolean x) {
		return x ? dataX.getIndex() : dataY.getIndex();
	}

}
