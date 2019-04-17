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

import functioncalls.graph.FcgVertex;
import functioncalls.graph.FunctionCallGraph;

/**
 * A class that takes a {@link FunctionCallGraph} vertex and determines which fill color 
 * should be used to paint
 */
public class FcgVertexPaintTransformer implements Function<FcgVertex, Paint> {

	private Color color;

	// only one color for now; may have more; these should be changeable via graph options
	public FcgVertexPaintTransformer(Color color) {
		this.color = color;
	}

	@Override
	public Paint apply(FcgVertex v) {
		return color;
	}

}
