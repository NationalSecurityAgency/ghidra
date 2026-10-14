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

public class BentoPixelMap {

	private long max;
	private double elementsPerPixel;
	private double multiplier;

	public BentoPixelMap(long elems, long pixels) {
		max = elems;
		elementsPerPixel = pixels <= 0 ? 0.0 : (double) elems / pixels;
		multiplier = 1.0;
	}

	public void createMapping(double mult) {
		this.multiplier = mult;
	}

	public long getOffset(int pixel) {
		if (multiplier == 0.0) {
			return 0;
		}
		return Math.round(pixel * elementsPerPixel / multiplier);
	}

	public int getPixel(long offset) {
		if (offset < 0) {
			offset = max;
		}
		double doffset = offset * multiplier / elementsPerPixel;
		return (int) Math.round(doffset);
	}

	public long getSize() {
		return getPixel(max);
	}

	public double getMultiplier() {
		return multiplier;
	}

	public double getOriginalElemPerPixel() {
		return elementsPerPixel;
	}
}
