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

import java.util.*;

public class BentoAxialData {

	private BentoProvider provider;
	private int index;

	// map - pixels to positions
	private BentoPixelMap pix2pos;
	// map - position to box
	private Map<Long, Set<BentoBox>> pos2box = new HashMap<>();
	// sorted values
	private TreeSet<Long> values = new TreeSet<>();
	// values indexed by position
	private Long[] valueArray = new Long[0];

	private int currentPixel = -1;
	private double zoomAmount = 1.0;


	public BentoAxialData(BentoProvider provider, int index) {
		this.provider = provider;
		this.index = index;
	}

	int initViews() {
		this.setMap(new BentoPixelMap(values.size(), values.size()));
		return values.size();
	}

	public void refresh() {
		if (pix2pos == null) {
			return;
		}
		pix2pos.createMapping(zoomAmount);
	}


	public void parseBoxes(Collection<BentoBox> boxes) {
		values.clear();
		pos2box.clear();

		if (boxes == null || boxes.isEmpty()) {
			valueArray = new Long[0];
			initViews();
			return;
		}

		for (BentoBox box : boxes) {
			BoundedObject obj = box.getObj(getIndex());
			if (obj != null) {
				values.add(obj.loBound);
				values.add(obj.hiBound);
			}
		}

		initViews();
		valueArray = values.toArray(new Long[0]);

		Map<Long, Integer> valueToIndexMap = new HashMap<>(valueArray.length);
		for (int i = 0; i < valueArray.length; i++) {
			valueToIndexMap.put(valueArray[i], i);
		}

		for (BentoBox box : boxes) {
			BoundedObject obj = box.getObj(getIndex());
			if (obj == null) {
				continue;
			}

			int startPos = valueToIndexMap.getOrDefault(obj.loBound, 0);
			int stopPos = valueToIndexMap.getOrDefault(obj.hiBound, 0);

			obj.setStart(startPos);
			obj.setStop(stopPos);

			pos2box.computeIfAbsent(obj.getStart(), _ -> new HashSet<>()).add(box);
			pos2box.computeIfAbsent(obj.getStop(), _ -> new HashSet<>()).add(box);
		}
	}

	public long getPos(int pixel) {
		if (pix2pos == null) {
			return 0;
		}
		return pix2pos.getOffset(pixel);
	}

	public String getTagForPos(Long position) {
		if (valueArray == null) {
			return "";
		}

		int pos = position == null ? (int) getPos(currentPixel) : position.intValue();

		if (pos >= 0 && pos < valueArray.length) {
			Long val = valueArray[pos];
			return provider.getRadix(index).format(val);
		}
		return "";
	}

	public double getZoom() {
		return zoomAmount;
	}

	public void scaleCurrentPixel(double changeAmount) {
		this.zoomAmount = (float) (zoomAmount * Math.pow(2.0, changeAmount));
		this.currentPixel = (int) (currentPixel * Math.pow(2.0, changeAmount));
	}

	public int getSizeValues() {
		return values.size();
	}

	public BentoPixelMap getMap() {
		return pix2pos;
	}

	public void setMap(BentoPixelMap map) {
		this.pix2pos = map;
	}

	public TreeSet<Long> getValues() {
		return values;
	}

	public void setValues(TreeSet<Long> values) {
		this.values = values;
		if (values != null) {
			this.valueArray = values.toArray(new Long[0]);
		}
	}

	public Long[] getArray() {
		return valueArray;
	}

	public Long[] setArray(Long[] array) {
		this.valueArray = array;
		return this.valueArray;
	}

	public Map<Long, Set<BentoBox>> getPosMap() {
		return pos2box;
	}

	public void setPosMap(Map<Long, Set<BentoBox>> pos2box) {
		this.pos2box = pos2box;
	}

	public int getCurrentPixel() {
		return currentPixel;
	}

	public void setCurrentPixel(int pixel) {
		this.currentPixel = pixel;
	}

	public int getIndex() {
		return index;
	}

	public void setIndex(int index) {
		this.index = index;
	}

}
