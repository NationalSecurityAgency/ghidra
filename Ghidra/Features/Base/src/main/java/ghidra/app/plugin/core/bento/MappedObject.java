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

public class MappedObject {

	private final BoundedObject obj;

	protected int pixStart;
	protected int pixEnd;
	protected int pixBound;

	public MappedObject(BoundedObject obj) {
		this.obj = obj;
	}

	public int getAddressPixelWidth() {
		int width = pixEnd - pixStart;
		return (width <= 0) ? 1 : width;
	}

	public int getPixelStart() {
		return pixStart;
	}

	public int getPixelWidth() {
		int currentEnd = pixEnd;
		if (currentEnd < pixStart) {
			currentEnd = pixBound;
		}

		int width = currentEnd - pixStart;
		return (width <= 0) ? 1 : width;
	}

	public boolean inPixelRange(long pos) {
		if (pos < pixStart) {
			return false;
		}
		if (pixEnd <= 0) {
			return true;
		}
		return pos <= pixEnd;
	}

	public void setBounds(BentoPixelMap map, int bound) {
		pixStart = map.getPixel(obj.getStart());
		pixEnd = map.getPixel(obj.getStop());
		pixBound = bound;
	}

}
