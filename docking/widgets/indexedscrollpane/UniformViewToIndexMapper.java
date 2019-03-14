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

public class UniformViewToIndexMapper implements ViewToIndexMapper {
	private int viewHeight;
	private int layoutHeight;
	private final IndexedScrollable scrollable;

	public UniformViewToIndexMapper(IndexedScrollable scrollable) {
		this.scrollable = scrollable;
		computeHeights();
	}

	private void computeHeights() {
		layoutHeight = scrollable.getHeight(BigInteger.ZERO);
		if (layoutHeight < 1) {
			layoutHeight = 1;
		}
		viewHeight = scrollable.getIndexCount().intValue()*layoutHeight;
	}

	@Override
	public int getViewHeight() {
		return viewHeight;
	}

	@Override
	public BigInteger getIndex(int value) {
		return BigInteger.valueOf(value/layoutHeight);
	}

	@Override
	public int getVerticalOffset(int value) {
		int index = value/layoutHeight;
		return (index*layoutHeight)-value;
	}

	@Override
	public void setVisibleViewHeight(int height) {
	}

	@Override
	public int getScrollValue(BigInteger startIndex, BigInteger endIndex, int startY, int endY) {
		int intValue = startIndex.intValue();
		return intValue*layoutHeight-startY;
	}

	@Override
	public void indexModelDataChanged(BigInteger start, BigInteger end) {
		computeHeights();
	}
}
