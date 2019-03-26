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

import java.math.BigInteger;
import java.util.Arrays;

public class PreMappedViewToIndexMapper implements ViewToIndexMapper {
	private IndexedScrollable model;
	private int viewHeight;
	private int[] layoutStarts;

	public PreMappedViewToIndexMapper(IndexedScrollable model) {
		this.model = model;
		createLayoutStarts();
	}

	private void createLayoutStarts() {
		int n = model.getIndexCount().intValue();
		layoutStarts = new int[n];
		int yPos = 0;
		for (int i = 0; i < n; i++) {
			layoutStarts[i] = yPos;
			int height = model.getHeight(BigInteger.valueOf(i));
			yPos += height;
		}
		viewHeight = yPos;
	}

	@Override
	public BigInteger getIndex(int value) {
		int index = Arrays.binarySearch(layoutStarts, value);
		if (index < 0) {
			index = -index - 2;
		}
		return BigInteger.valueOf(index);
	}

	@Override
	public int getScrollValue(BigInteger startIndex, BigInteger endIndex, int startY, int endY) {
		if (layoutStarts.length == 0) {

			return 0;
		}

		return layoutStarts[startIndex.intValue()] - startY;
	}

	@Override
	public int getVerticalOffset(int value) {
		if (layoutStarts.length == 0) {
			return 0;
		}

		int index = Arrays.binarySearch(layoutStarts, value);
		if (index >= 0) {
			return 0;
		}
		index = -index - 2;
		return layoutStarts[index] - value;
	}

	@Override
	public int getViewHeight() {
		return viewHeight;
	}

	@Override
	public void setVisibleViewHeight(int height) {
		// height is irrelevant to us, as we map our entire layout structure ahead of time
	}

	@Override
	public void indexModelDataChanged(BigInteger start, BigInteger end) {
		int startIndex = start.intValue();
		int endIndex = Math.min(layoutStarts.length, end.intValue() + 1);
		int yPos = layoutStarts[startIndex];
		for (int i = startIndex; i < endIndex; i++) {
			layoutStarts[i] = yPos;
			int height = model.getHeight(BigInteger.valueOf(i));
			yPos += height;
		}
		if (endIndex < layoutStarts.length) {
			int diff = yPos - layoutStarts[endIndex];
			for (int i = endIndex; i < layoutStarts.length; i++) {
				layoutStarts[i] = layoutStarts[i] + diff;
			}
			viewHeight += diff;
		}
		else {
			viewHeight = yPos;
		}
	}

}
