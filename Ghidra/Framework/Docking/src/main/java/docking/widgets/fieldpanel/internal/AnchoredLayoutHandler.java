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
package docking.widgets.fieldpanel.internal;

import java.math.BigInteger;
import java.util.*;

import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.support.AnchoredLayout;

public class AnchoredLayoutHandler {

	private final LayoutModel model;
	private int viewHeight;
	private final LinkedList<AnchoredLayout> layouts = new LinkedList<>();

	public AnchoredLayoutHandler(LayoutModel model, int viewHeight) {
		this.model = model;
		this.viewHeight = viewHeight;
	}

	public List<AnchoredLayout> positionLayoutsAroundAnchor(BigInteger anchorIndex,
			int viewPosition) {
		layouts.clear();

		AnchoredLayout layout = getClosestLayout(anchorIndex, viewPosition);
		if (layout != null) {
			layouts.add(layout);
			fillOutLayouts();
		}
		return new ArrayList<>(layouts);
	}

	public List<AnchoredLayout> shiftViewDownOneRow() {
		if (layouts.isEmpty()) {
			return new ArrayList<>();
		}
		AnchoredLayout layout = layouts.getFirst();
		int yPos = layout.getYPos();
		int scrollAmount = layout.getScrollableUnitIncrement(-yPos, 1);
		return shiftView(scrollAmount);
	}

	public List<AnchoredLayout> shiftViewUpOneRow() {
		if (layouts.isEmpty()) {
			return new ArrayList<>();
		}
		int scrollAmount = 0;
		AnchoredLayout layout = layouts.getFirst();
		BigInteger index = layout.getIndex();
		int yPos = layout.getYPos();

		if (yPos == 0) {
			layout = getPreviousLayout(index, yPos);
			if (layout == null) {
				return new ArrayList<>(layouts);
			}
			layouts.add(0, layout);
			yPos = layout.getYPos();
		}

		scrollAmount = layout.getScrollableUnitIncrement(-yPos, -1);
		return shiftView(scrollAmount);
	}

	public List<AnchoredLayout> shiftViewDownOnePage() {
		if (layouts.isEmpty()) {
			return new ArrayList<>();
		}
		AnchoredLayout last = layouts.getLast();
		int diff = last.getScrollableUnitIncrement(viewHeight - last.getYPos(), -1);
		return shiftView(viewHeight + diff);
	}

	public List<AnchoredLayout> shiftViewUpOnePage() {
		if (layouts.isEmpty()) {
			return new ArrayList<>();
		}
		int scrollAmount = viewHeight;
		AnchoredLayout first = layouts.getFirst();
		if (first.getYPos() != 0) {
			int diff = first.getScrollableUnitIncrement(-first.getYPos(), 1);
			if (diff < viewHeight) {
				scrollAmount -= diff;
			}
		}
		shiftView(-scrollAmount);

		first = layouts.getFirst();
		if (first.getYPos() != 0) {
			return shiftViewDownOneRow();
		}
		return new ArrayList<>(layouts);
	}

	public List<AnchoredLayout> shiftView(int viewAmount) {
		repositionLayouts(-viewAmount);
		fillOutLayouts();
		return new ArrayList<>(layouts);
	}

	public List<AnchoredLayout> setViewHeight(int viewHeight) {
		this.viewHeight = viewHeight;
		if (layouts.isEmpty()) {
			return positionLayoutsAroundAnchor(BigInteger.ZERO, 0);
		}
		fillOutLayouts();
		return new ArrayList<>(layouts);
	}

	private void fillOutLayouts() {
		if (layouts.isEmpty()) {
			return;
		}
		AnchoredLayout lastLayout = layouts.getLast();
		fillLayoutsForward(lastLayout.getIndex(), lastLayout.getYPos() + lastLayout.getHeight());
		lastLayout = layouts.getLast();
		if (lastLayout.getEndY() < viewHeight) {
			repositionLayouts(viewHeight - lastLayout.getEndY());
		}

		AnchoredLayout firstLayout = layouts.getFirst();
		fillLayoutsBack(firstLayout.getIndex(), firstLayout.getYPos());
		firstLayout = layouts.getFirst();
		if (firstLayout.getYPos() > 0) {
			repositionLayouts(-firstLayout.getYPos());
		}

		lastLayout = layouts.getLast();
		fillLayoutsForward(lastLayout.getIndex(), lastLayout.getYPos() + lastLayout.getHeight());

		trimLayouts();
	}

	private void repositionLayouts(int amount) {
		for (AnchoredLayout layout : layouts) {
			layout.setYPos(layout.getYPos() + amount);
		}
	}

	private void trimLayouts() {
		Iterator<AnchoredLayout> it = layouts.iterator();
		while (it.hasNext()) {
			AnchoredLayout layout = it.next();
			int y = layout.getYPos();
			int height = layout.getHeight();
			if ((y + height <= 0) || (y > viewHeight)) {
				it.remove();
			}
		}
	}

	private void fillLayoutsForward(BigInteger existingLastIndex, int y) {
		BigInteger index = existingLastIndex;
		while (y < viewHeight) {
			AnchoredLayout nextLayout = getNextLayout(index, y);
			if (nextLayout == null) {
				return;
			}
			layouts.add(nextLayout);
			y += nextLayout.getHeight();
			index = nextLayout.getIndex();
		}
	}

	private void fillLayoutsBack(BigInteger existingFirstIndex, int y) {
		BigInteger index = existingFirstIndex;
		while (y > 0) {
			AnchoredLayout prevLayout = getPreviousLayout(index, y);
			if (prevLayout == null) {
				return;
			}
			layouts.addFirst(prevLayout);
			y = y - prevLayout.getHeight();
			index = prevLayout.getIndex();
		}
	}

	private AnchoredLayout getPreviousLayout(BigInteger index, int yPos) {
		while ((index = model.getIndexBefore(index)) != null) {
			Layout layout = model.getLayout(index);
			if (layout != null) {
				return new AnchoredLayout(layout, index, yPos - layout.getHeight());
			}
		}
		return null;
	}

	private AnchoredLayout getNextLayout(BigInteger index, int yPos) {
		while ((index = model.getIndexAfter(index)) != null) {
			Layout layout = model.getLayout(index);
			if (layout != null) {
				return new AnchoredLayout(layout, index, yPos);
			}
		}
		return null;
	}

	private AnchoredLayout getClosestLayout(BigInteger index, int y) {
		Layout layout = model.getLayout(index);
		if (layout != null) {
			return new AnchoredLayout(layout, index, y);
		}
		AnchoredLayout nextLayout = getNextLayout(index, y);
		if (nextLayout != null) {
			return nextLayout;
		}
		AnchoredLayout previousLayout = getPreviousLayout(index, y);
		if (previousLayout != null) {
			previousLayout.setYPos(y);
			return previousLayout;
		}
		return null;
	}
}
