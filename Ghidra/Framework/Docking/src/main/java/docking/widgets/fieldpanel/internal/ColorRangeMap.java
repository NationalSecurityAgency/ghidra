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
package docking.widgets.fieldpanel.internal;

import ghidra.util.datastruct.*;

import java.awt.Color;


public class ColorRangeMap {
	private RangeMap map;
	private ValueRange valueRange;
	private Color lastColor;
	private int lastColorValue;

	public ColorRangeMap() {
		map = new RangeMap();
		valueRange = map.getValueRange(0);
		
	}

	public void color(long start, long end, Color c) {
		int colorValue = c.getRGB();
		map.paintRange(start, end, colorValue);
		valueRange = map.getValueRange(0);
	}
	public void clear(long start, long end) {
		map.paintRange(start, end, 0);
		valueRange = map.getValueRange(0);
	}
	public void clear() {
		map.clear();
		valueRange = map.getValueRange(0);
	}
	public Color getColor(long index, Color defaultColor) {
		if (!valueRange.contains(index)) {
			valueRange = map.getValueRange(index);
		}
		int colorValue = valueRange.getValue();
		if (colorValue == 0) {
			return defaultColor;
		}
		return getColor(valueRange.getValue());
	}
	private Color getColor(int colorValue) {
		if (lastColorValue == colorValue) {
			return lastColor;
		}
		lastColorValue = colorValue;
		lastColor = new Color(colorValue);
		return lastColor;
	}
	public ColorRangeMap copy() {
		ColorRangeMap newMap = new ColorRangeMap();
		IndexRangeIterator it = map.getIndexRangeIterator(-1);
		while(it.hasNext()) {
			IndexRange ir = it.next();
			int colorValue = map.getValue(ir.getStart());
			newMap.map.paintRange(ir.getStart(), ir.getEnd(), colorValue);
		}
		newMap.valueRange = map.getValueRange(0);
		return newMap;
	}
}
