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
package functioncalls.graph.renderer;

import java.awt.Color;
import java.awt.Paint;

import com.google.common.base.Function;

import functioncalls.graph.FcgEdge;

/**
 * Generates colors for a given {@link FcgEdge}
 */
public class FcgEdgePaintTransformer implements Function<FcgEdge, Paint> {

	// private static final Paint LESS_IMPORTANT_COLOR = new Color(125, 125, 125, 75);
	private Color directColor;
	private Color indirectColor;

	private Color[] directColorWithAlpha = new Color[10];

	// only one color for now; may have more; these should be changeable via graph options
	public FcgEdgePaintTransformer(Color directColor, Color indirectColor) {
		this.directColor = directColor;
		this.indirectColor = indirectColor;

		directColorWithAlpha = alphatize(directColor);
	}

	private Color[] alphatize(Color c) {
		Color[] alphad = new Color[10];
		alphad[0] = c;
		for (int i = 1; i < 10; i++) {
			double newAlpha = 255 - (i * 25.5);
			alphad[i] = new Color(c.getRed(), c.getGreen(), c.getBlue(), (int) newAlpha);
		}
		return alphad;
	}

	@Override
	public Paint apply(FcgEdge e) {
		if (e.isDirectEdge()) {
			return getDirectEdgeColor(e);
		}

		return indirectColor;
	}

	private Color getDirectEdgeColor(FcgEdge e) {

		return directColor;

		/*// this allows us to make the edges fainter as the outward levels increase
		FcgVertex start = e.getStart();
		FcgVertex end = e.getEnd();
		FcgLevel sl = start.getLevel();
		FcgLevel el = end.getLevel();
		int level = Math.min(sl.getDistance(), el.getDistance());
		level = Math.min(level, 9);
		Color c = directColorWithAlpha[level];
		return c;
		*/
	}
}
