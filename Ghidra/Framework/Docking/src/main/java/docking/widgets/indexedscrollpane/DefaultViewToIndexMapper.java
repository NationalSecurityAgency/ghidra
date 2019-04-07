/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package docking.widgets.indexedscrollpane;

import java.math.BigDecimal;
import java.math.BigInteger;

public class DefaultViewToIndexMapper implements ViewToIndexMapper {
	private static int MAX_SCROLL_VALUE = Integer.MAX_VALUE/2; //at max value, java has bug
	private static double AVERAGE_HEIGHT = 20;

	private BigInteger lastIndex;
	private BigInteger lastStartIndex;
	private double xFactor;
	private int screenHeight;
	private int viewHeight;
	private boolean endValidated;
	private final IndexedScrollable model;
	private int lastStartY = 0;

	public DefaultViewToIndexMapper(IndexedScrollable model, int screenHeight) {
		this.model = model;
		this.screenHeight = screenHeight;
		resetState();
	}

	private void resetState() {
		lastIndex = model.getIndexCount().subtract(BigInteger.ONE);
		double totalHeight = model.getIndexCount().doubleValue() * AVERAGE_HEIGHT;

		if (totalHeight > MAX_SCROLL_VALUE) {
			viewHeight = MAX_SCROLL_VALUE;
		}
		else {
			viewHeight = (int)totalHeight;
		}
		xFactor = lastIndex.doubleValue()/(viewHeight - screenHeight);
		lastStartIndex = lastIndex;
		lastStartY = 0;
		endValidated = false;
	}

	@Override
	public BigInteger getIndex(int value) {
		if (value == viewHeight-screenHeight ) {
			return lastIndex;
		}
		double dindex = value*xFactor;
		BigDecimal bindex = BigDecimal.valueOf(dindex);
		return bindex.toBigInteger();
	}

	@Override
	public int getVerticalOffset(int value) {
		return 0;
	}

	@Override
	public int getViewHeight() {
		return viewHeight;
	}

	@Override
	public void setVisibleViewHeight(int screenHeight) {
		this.screenHeight = screenHeight;
		resetState();
	}

	@Override
	public int getScrollValue(BigInteger startIndex, BigInteger endIndex, int startY, int endY) {
		if (!endValidated) {
			if (endIndex.equals(lastIndex) && endY<=screenHeight) {
				lastStartIndex = startIndex;
				lastStartY = startY;
				xFactor = startIndex.doubleValue()/(viewHeight - screenHeight);
				endValidated = true;
			}
		}

		if (startIndex.equals(BigInteger.ZERO) && startY == 0) {
			return 0;
		}

		if (startIndex.equals(lastStartIndex) && startY == lastStartY) {
			return viewHeight-screenHeight;
		}

		double scrollValue = startIndex.doubleValue() / xFactor;
		int value = (int)(scrollValue + 0.5);

		if (value == 0) {
			return 1;
		}

		if (value >= viewHeight-screenHeight) {
			return viewHeight-screenHeight-1;
		}
		return value;
	}

	@Override
	public void indexModelDataChanged(BigInteger start, BigInteger end) {
		if (end.compareTo(lastIndex) >= 0) {
			resetState();
		}
	}

}
