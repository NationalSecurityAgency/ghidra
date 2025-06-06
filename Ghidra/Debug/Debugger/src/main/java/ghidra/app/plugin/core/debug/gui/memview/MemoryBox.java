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

import java.awt.Color;
import java.awt.Graphics;
import java.util.HashMap;
import java.util.Map;

import generic.theme.GThemeDefaults.Colors;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.time.schedule.TraceSchedule.TimeRadix;

public class MemoryBox {

	protected final Trace trace;
	protected String id;
	protected MemviewBoxType type;
	protected AddressRange range;
	protected long start;
	protected long stop = Long.MAX_VALUE;
	protected long startAddr;
	protected long stopAddr = -1;
	protected long startTime;
	protected long stopTime = -1;

	protected int pixAstart;
	protected int pixAend;
	protected int boundA;
	protected int pixTstart;
	protected int pixTend;
	protected int boundT;
	protected Color color;

	protected boolean current;

	public MemoryBox(Trace trace, String id, MemviewBoxType type, AddressRange range, long tick,
			Color color) {
		this.trace = trace;
		this.id = id;
		this.type = type;
		this.range = range;
		this.start = tick;
		this.color = color;
	}

	public MemoryBox(Trace trace, String id, MemviewBoxType type, AddressRange range, long tick) {
		this(trace, id, type, range, tick, type.getColor());
	}

	public MemoryBox(Trace trace, String id, MemviewBoxType type, AddressRange range,
			Lifespan trange) {
		this(trace, id, type, range, trange.lmin());
		setEnd(trange.lmax());
	}

	public String getId() {
		return id;
	}

	public MemviewBoxType getType() {
		return type;
	}

	public AddressRange getRange() {
		return range;
	}

	public Lifespan getSpan() {
		return Lifespan.span(start, stop);
	}

	public long getStart() {
		return start;
	}

	public long getEnd() {
		return stop;
	}

	public void setEnd(long tick) {
		this.stop = stop < tick ? stop : tick;
	}

	public Color getColor() {
		return color;
	}

	public void setColor(Color color) {
		this.color = color;
	}

	public int getAddressPixelStart() {
		return pixAstart;
	}

	public int getAddressPixelWidth() {
		if (pixAend - pixAstart <= 0) {
			return 1;
		}
		return pixAend - pixAstart;
	}

	public int getTimePixelStart() {
		return pixTstart;
	}

	public int getTimePixelWidth() {
		if (pixTend < pixTstart) {
			pixTend = boundT;
		}
		if (pixTend - pixTstart == 0) {
			return 1;
		}
		return pixTend - pixTstart;
	}

	public int getX(boolean vertical) {
		return vertical ? pixTstart : pixAstart;
	}

	public int getY(boolean vertical) {
		return vertical ? pixAstart : pixTstart;
	}

	public void setCurrent(boolean current) {
		this.current = current;
	}

	public boolean isCurrent() {
		return current;
	}

	public void render(Graphics g, boolean vertical) {
		int x = vertical ? getTimePixelStart() : getAddressPixelStart();
		int w = vertical ? getTimePixelWidth() : getAddressPixelWidth();
		int y = vertical ? getAddressPixelStart() : getTimePixelStart();
		int h = vertical ? getAddressPixelWidth() : getTimePixelWidth();
		g.setColor(Colors.BORDER);
		g.fillRect(x - 1, y - 1, w + 2, h + 2);
		g.setColor(color);
		g.fillRect(x, y, w, h);
	}

	public void renderBA(Graphics g, boolean vertical, int sz) {
		int x = vertical ? 0 : getAddressPixelStart();
		int w = vertical ? sz : getAddressPixelWidth();
		int y = vertical ? getAddressPixelStart() : 0;
		int h = vertical ? getAddressPixelWidth() : sz;
		g.setColor(Colors.BORDER);
		g.fillRect(x - 1, y - 1, w + 2, h + 2);
		g.setColor(color);
		g.fillRect(x, y, w, h);
	}

	public void renderBT(Graphics g, boolean vertical, int sz, int bound) {
		int x = vertical ? getTimePixelStart() : 0;
		int w = vertical ? 1 : sz;
		int y = vertical ? 0 : getTimePixelStart();
		int h = vertical ? sz : 1;
		g.setColor(Colors.BORDER);
		g.fillRect(x - 1, y - 1, w + 2, h + 2);
		g.setColor(color);
		g.fillRect(x, y, w, h);
	}

	public void setAddressBounds(MemviewMap map, int bound) {
		if (stopAddr < 0) {
			stopAddr = startAddr;
		}
		pixAstart = getPixel(map, startAddr, bound);
		pixAend = getPixel(map, stopAddr, bound);
		boundA = bound;
	}

	public void setTimeBounds(MemviewMap map, int bound) {
		pixTstart = getPixel(map, startTime, bound);
		pixTend = getPixel(map, stopTime, bound);
		boundT = bound;
	}

	protected int getPixel(MemviewMap map, long offset, int bound) {
		return map.getPixel(offset);
	}

	public long getStartAddress() {
		return startAddr;
	}

	public void setStartAddress(long val) {
		startAddr = val;
	}

	public long getStopAddress() {
		return stopAddr;
	}

	public void setStopAddress(long val) {
		stopAddr = val;
	}

	public long getStartTime() {
		return startTime;
	}

	public void setStartTime(long val) {
		startTime = val;
	}

	public long getStopTime() {
		return stopTime;
	}

	public void setStopTime(long val) {
		stopTime = val;
	}

	private TimeRadix getTimeRadix() {
		return trace.getTimeManager().getTimeRadix();
	}

	public String formatStart() {
		return getTimeRadix().format(start);
	}

	public String formatEnd() {
		return getTimeRadix().format(stop);
	}

	public boolean inPixelRange(long pos) {
		if (pos < pixTstart) {
			return false;
		}
		if (pixTend <= 0) {
			return true;
		}
		return pos <= pixTend;
	}

	public Map<String, Object> getAttributeMap() {
		Map<String, Object> map = new HashMap<>();
		map.put("Id", getId());
		map.put("StartAddr", getStartAddress());
		map.put("StopAddr", getStopAddress());
		map.put("StartTime", getStartTime());
		map.put("StopTIme", getStopTime());
		return map;
	}
}
