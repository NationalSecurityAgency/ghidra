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
package ghidra.app.plugin.core.overview.entropy;

import java.awt.Color;

/**
 * Entropy information for the Entropy color legend panel. A KnotRecord records a "known" entropy
 * range for a specific type of data in a program.  For example, if you compute the entropy for
 * a range of bytes containing ASCII characters, you will get an entropy score close to 4.7.
 */
public class KnotRecord {
	public String name;
	public Color color;
	public int start;
	public int end;
	public int point;

	/**
	 * Constructor
	 *
	 * @param name a name for what this range represents. (ASCII, X86 code, etc.)
	 * @param color the color to associate with this type.
	 * @param start the minimum entropy for this range.
	 * @param end the maximum entropy for this range.
	 * @param point the x coordinate in the legend for this knot.
	 */
	public KnotRecord(String name, Color color, int start, int end, int point) {
		this.name = name;
		this.color = color;
		this.start = start;
		this.end = end;
		this.point = point;
	}

	public String getName() {
		return name;
	}

	public boolean contains(int entropy) {
		return entropy >= start && entropy <= end;
	}

}
