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
package ghidra.app.decompiler.component.margin;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import docking.widgets.fieldpanel.support.AnchoredLayout;

/**
 * An implementation of {@link LayoutPixelIndexMap} for vertical coordinates
 * 
 * <p>
 * This class implements {@link #getIndex(int)} in log time and {@link #getPixel(BigInteger)} in
 * constant time.
 */
public class VerticalLayoutPixelIndexMap implements LayoutPixelIndexMap {
	private BigInteger base = BigInteger.ZERO;
	private int[] yPositions = new int[0];
	private int size;

	@Override
	public int getPixel(BigInteger index) {
		return yPositions[index.subtract(base).intValueExact()];
	}

	protected int computeOff(int pixel) {
		int result = Arrays.binarySearch(yPositions, 0, size, pixel);
		if (result >= 0) {
			return result;
		}
		// result = -insertionPoint - 1, first index where acc[index] > pixel
		// want index = insertionPoint - 1, index where acc[index] < pixel < acc[index+1]
		// insertionPoint = -result - 1
		// index = -result - 2;
		return -result - 2;
	}

	@Override
	public BigInteger getIndex(int pixel) {
		return base.add(BigInteger.valueOf(computeOff(pixel)));
	}

	public void layoutsChanged(List<AnchoredLayout> layouts) {
		size = layouts.size();
		if (yPositions.length < size) {
			yPositions = new int[size];
		}
		int i = 0;
		base = layouts.isEmpty() ? BigInteger.ZERO : layouts.get(0).getIndex();
		for (AnchoredLayout l : layouts) {
			assert l.getIndex().subtract(base).intValueExact() == i;
			yPositions[i] = l.getYPos();
			i++;
		}
	}
}
