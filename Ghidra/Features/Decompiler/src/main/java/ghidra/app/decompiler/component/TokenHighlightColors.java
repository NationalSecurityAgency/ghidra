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
package ghidra.app.decompiler.component;

import java.awt.Color;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.collections4.map.LazyMap;

// TODO docme
public class TokenHighlightColors {

	private int minColorSaturation = 100;
	private int defaultColorAlpha = 100;
	private Map<String, Color> colorsByName =
		LazyMap.lazyMap(new HashMap<>(), s -> generateColor());

	private Color generateColor() {
		return new Color((int) (minColorSaturation + Math.random() * (256 - minColorSaturation)),
			(int) (minColorSaturation + Math.random() * (256 - minColorSaturation)),
			(int) (minColorSaturation + Math.random() * (256 - minColorSaturation)),
			defaultColorAlpha);
	}

	public Color getColor(String text) {
		return colorsByName.get(text);
	}
}
