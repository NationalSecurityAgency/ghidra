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
package ghidra.app.plugin.core.debug.gui.memview;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

public class MemviewPanel extends JPanel implements MouseListener, MouseMotionListener {
	private static final long serialVersionUID = 1L;

	private MemviewProvider provider;
	private MemviewMap amap;
	private MemviewMap tmap;
	private List<MemoryBox> boxList = new ArrayList<MemoryBox>();

	private int pressedX;
	private int pressedY;
	private boolean enableDrag = false;
	private boolean ctrlPressed = false;
	private int barWidth = 1000;
	private int barHeight = 500;
	private boolean vertical = false;

	private int currentPixelAddr = -1;
	private int currentPixelTime = -1;
	private Rectangle currentRectangle = null;

	private List<MemoryBox> blist = null;
	private Map<String, MemoryBox> bmap = new HashMap<>();

	private TreeSet<Address> addresses = new TreeSet<>();
	private TreeSet<Long> times = new TreeSet<>();
	private Address[] addressArray;
	private Long[] timesArray;
	private Map<Long, Set<MemoryBox>> addr2box = new HashMap<>();
	private Map<Long, Set<MemoryBox>> time2box = new HashMap<>();

	public MemviewPanel(MemviewProvider provider) {
		super();
		this.provider = provider;
		setPreferredSize(new Dimension(barWidth, barHeight));
		setSize(getPreferredSize());
		setBorder(BorderFactory.createLineBorder(Color.BLACK, 1));
		setFocusable(true);

		addMouseListener(this);
		addMouseMotionListener(this);
		ToolTipManager.sharedInstance().registerComponent(this);
	}

	@Override
	public Dimension getPreferredSize() {
		int asz = amap != null ? (int) (amap.getSize()) : 500;
		int tsz = tmap != null ? (int) (tmap.getSize()) : 500;
		int w = vertical ? tsz : asz;
		int h = vertical ? asz : tsz;
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
		if (vertical && clip.height > height || !vertical && clip.width > width) {
			refresh();
			return;
		}

		g.fillRect(0, 0, width, height);

		for (MemoryBox box : boxList) {
			box.render(g, vertical);
		}

		//Draw the current location arrow
		if (currentPixelAddr >= 0) {
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
		Graphics2D g2 = (Graphics2D) g;
		if (vertical) {
			g2.rotate(90.0f / 180.0f * Math.PI);
			g2.translate(0, LOCATION_ARROW_HEIGHT);
			g.translate(currentPixelAddr, -currentPixelTime);
			g2.rotate(Math.PI);
		}
		else {
			g2.translate(0, -LOCATION_ARROW_HEIGHT);
			g.translate(currentPixelAddr, currentPixelTime);
		}

		g.setColor(Color.RED);
		g.fillPolygon(locXs, locYs, locXs.length);

		if (vertical) {
			g2.rotate(Math.PI);
			g.translate(-currentPixelAddr, currentPixelTime);
			g2.translate(0, -LOCATION_ARROW_HEIGHT);
			g2.rotate(-90.0f / 180.0f * Math.PI);
		}
		else {
			g.translate(-currentPixelAddr, -currentPixelTime);
			g2.translate(0, LOCATION_ARROW_HEIGHT);
		}
	}

	private void drawFrame(Graphics g) {
		int x = currentRectangle.x;
		int y = currentRectangle.y;
		int w = currentRectangle.width;
		int h = currentRectangle.height;
		g.setColor(Color.RED);
		g.fillRect(x - 1, y - 1, 1, h + 2);
		g.fillRect(x - 1, y - 1, w + 2, 1);
		g.fillRect(x + w + 1, y - 1, 1, h + 2);
		g.fillRect(x - 1, y + h + 1, w + 2, 1);
	}

	void initViews() {
		setSize(new Dimension(vertical ? times.size() : addresses.size(),
			vertical ? addresses.size() : times.size()));
		this.amap = new MemviewMap(addresses.size(), addresses.size());
		this.tmap = new MemviewMap(times.size(), times.size());
	}

	public void refresh() {
		if (amap == null || tmap == null) {
			return;
		}
		if (vertical) {
			amap.createMapping(provider.getZoomAmountA());
			tmap.createMapping(provider.getZoomAmountT());
		}
		else {
			amap.createMapping(provider.getZoomAmountA());
			tmap.createMapping(provider.getZoomAmountT());
		}

		updateBoxes();
	}

	void updateBoxes() {
		if (!this.isShowing())
			return;

		boxList = new ArrayList<MemoryBox>();
		Collection<MemoryBox> boxes = getBoxes();
		if (boxes == null) {
			return;
		}
		for (MemoryBox box : boxes) {
			if (box == null)
				continue;

			int bound = vertical ? getHeight() - 1 : getWidth() - 1;
			box.setAddressBounds(amap, bound);
			bound = vertical ? getWidth() - 1 : getHeight() - 1;
			box.setTimeBounds(tmap, bound);

			boxList.add(box);
		}

		repaint(0, 0, getWidth(), getHeight());
	}

	@Override
	public void mousePressed(MouseEvent e) {
		requestFocus();  // COMPONENT

		ctrlPressed = false;
		currentRectangle = null;

		if (e.getButton() == MouseEvent.BUTTON1) {
			enableDrag = true;
			pressedX = e.getX();
			pressedY = e.getY();
			currentPixelAddr = vertical ? pressedY : pressedX;
			currentPixelTime = vertical ? pressedX : pressedY;
			provider.selectTableEntry(getBoxesAt(pressedX, pressedY));
			provider.refresh();
		}

		if (e.getButton() == MouseEvent.BUTTON2) {
			System.err.println("BUTTON2");
		}

		if (e.getButton() == MouseEvent.BUTTON3) {
			ctrlPressed = true;
			enableDrag = true;
			pressedX = e.getX();
			pressedY = e.getY();
		}
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		enableDrag = false;
	}

	@Override
	public void mouseClicked(MouseEvent e) {
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
				provider.goTo(pressedX - e.getX(), pressedY - e.getY());
			}
			else {
				currentRectangle =
					new Rectangle(pressedX, pressedY, e.getX() - pressedX, e.getY() - pressedY);
				provider.selectTableEntry(getBoxesIn(currentRectangle));
				provider.refresh();
			}
		}
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		// Nothing to do
	}

	public void setSelection(Set<MemoryBox> boxes) {
		for (MemoryBox memoryBox : boxes) {
			currentPixelAddr = memoryBox.pixAstart;
			currentPixelTime = memoryBox.pixTstart;
			refresh();
		}
	}

	public String getTitleAnnotation() {
		if (currentPixelAddr < 0 || addressArray == null) {
			return "";
		}
		String aval = getTagForAddr(currentPixelAddr);
		String tval = getTagForTick(currentPixelTime);
		String vals = vertical ? tval + ":" + aval : aval + ":" + tval;
		return "curpos=[" + vals + "]";
	}

	public Set<MemoryBox> getBoxesAt(int x, int y) {
		long addr = getAddr(x, y);
		long tick = getTick(x, y);
		long pos = vertical ? x : y;
		Set<MemoryBox> matches = new HashSet<>();
		Set<MemoryBox> mboxes = addr2box.get(addr);
		if (mboxes != null && tick < timesArray.length) {
			for (MemoryBox memoryBox : mboxes) {
				if (memoryBox.inPixelRange(pos)) {
					matches.add(memoryBox);
				}
			}
		}
		return matches;
	}

	public Set<MemoryBox> getBoxesIn(Rectangle r) {
		long startAddr = getAddr(r.x, r.y);
		long startTick = getTick(r.x, r.y);
		long stopAddr = getAddr(r.x + r.width, r.y + r.height);
		long stopTick = getTick(r.x + r.width, r.y + r.height);
		Set<MemoryBox> matches = new HashSet<>();
		for (long addr = startAddr; addr < stopAddr; addr++) {
			Set<MemoryBox> mboxes = addr2box.get(addr);
			for (MemoryBox memoryBox : mboxes) {
				if (memoryBox.getStartTime() >= startTick || memoryBox.getStopTime() <= stopTick) {
					matches.add(memoryBox);
				}
			}
		}
		return matches;
	}

	@Override
	public String getToolTipText(MouseEvent e) {
		if (amap == null || tmap == null) {
			return e.getX() + ":" + e.getY();
		}
		long addr = getAddr(e.getX(), e.getY());
		long tick = getTick(e.getX(), e.getY());
		String aval = getTagForAddr(addr);
		String tval = getTagForTick(tick);
		Set<MemoryBox> boxes = getBoxesAt(e.getX(), e.getY());
		for (MemoryBox memoryBox : boxes) {
			aval = memoryBox.getId();
		}
		return vertical ? tval + ":" + aval : aval + ":" + tval;
	}

	private void parseBoxes(Collection<MemoryBox> boxes) {
		addresses.clear();
		times.clear();
		addr2box.clear();
		time2box.clear();

		for (MemoryBox box : boxes) {
			AddressRange range = box.getRange();
			if (range != null) {
				addresses.add(range.getMinAddress());
				addresses.add(range.getMaxAddress());
			}
			long start = box.getStart();
			long end = box.getEnd();
			times.add(start);
			times.add(end);
		}

		initViews();
		addressArray = new Address[addresses.size()];
		timesArray = new Long[times.size()];
		addresses.toArray(addressArray);
		times.toArray(timesArray);

		for (MemoryBox box : boxes) {
			AddressRange range = box.getRange();
			if (range != null) {
				box.setStartAddress(addresses.headSet(range.getMinAddress()).size());
				box.setStopAddress(addresses.headSet(range.getMaxAddress()).size());
			}
			box.setStartTime(times.headSet(box.getStart()).size());
			box.setStopTime(times.headSet(box.getEnd()).size());

			Set<MemoryBox> mboxes = addr2box.get(box.getStartAddress());
			if (mboxes == null) {
				mboxes = new HashSet<MemoryBox>();
			}
			mboxes.add(box);
			addr2box.put(box.getStartAddress(), mboxes);
			mboxes = addr2box.get(box.getStopAddress());
			if (mboxes == null) {
				mboxes = new HashSet<MemoryBox>();
			}
			mboxes.add(box);
			addr2box.put(box.getStopAddress(), mboxes);

			mboxes = time2box.get(box.getStartTime());
			if (mboxes == null) {
				mboxes = new HashSet<MemoryBox>();
			}
			mboxes.add(box);
			time2box.put(box.getStartTime(), mboxes);
			mboxes = time2box.get(box.getStopTime());
			if (mboxes == null) {
				mboxes = new HashSet<MemoryBox>();
			}
			mboxes.add(box);
			time2box.put(box.getStopTime(), mboxes);
		}
		refresh();
	}

	public List<MemoryBox> getBoxes() {
		return blist;
	}

	public void setBoxes(List<MemoryBox> boxes) {
		this.blist = boxes;
		for (MemoryBox b : boxes) {
			bmap.put(b.getId(), b);
		}
		parseBoxes(blist);
	}

	public void addBoxes(List<MemoryBox> boxes) {
		if (blist == null) {
			blist = new ArrayList<MemoryBox>();
		}
		for (MemoryBox b : boxes) {
			if (bmap.containsKey(b.getId())) {
				MemoryBox box = bmap.get(b.getId());
				blist.remove(box);
			}
			blist.add(b);
			bmap.put(b.getId(), b);
		}
		parseBoxes(blist);
	}

	public void reset() {
		blist = new ArrayList<MemoryBox>();
		bmap.clear();
		parseBoxes(blist);
	}

	void setAddressPixelMap(MemviewMap map) {
		this.amap = map;
	}

	void setTimePixelMap(MemviewMap tmap) {
		this.tmap = tmap;
	}

	public boolean getVerticalMode() {
		return vertical;
	}

	public void setVerticalMode(boolean vertical) {
		this.vertical = vertical;
	}

	public long getAddr(int x, int y) {
		if (amap == null)
			return 0;
		return vertical ? amap.getOffset(y) : amap.getOffset(x);
	}

	public long getTick(int x, int y) {
		if (tmap == null)
			return 0;
		return vertical ? tmap.getOffset(x) : tmap.getOffset(y);
	}

	public String getTagForAddr(long addr) {
		String aval = "";
		if (0 <= addr && addr < addressArray.length) {
			aval = addressArray[(int) addr].toString();
		}
		return aval;
	}

	public String getTagForTick(long tick) {
		String tval = "";
		if (0 <= tick && tick < timesArray.length) {
			tval = Long.toString(timesArray[(int) tick]);
		}
		return tval;
	}

	public void scaleCurrentPixelAddr(double changeAmount) {
		this.currentPixelAddr = (int) (currentPixelAddr * Math.pow(2.0, changeAmount));
	}

	public void scaleCurrentPixelTime(double changeAmount) {
		this.currentPixelTime = (int) (currentPixelTime * Math.pow(2.0, changeAmount));
	}

}
