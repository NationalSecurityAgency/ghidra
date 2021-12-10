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
package ghidra.service.graph;

import java.util.Arrays;
import java.util.List;

/** 
 * Just a static list of graph layout algorithm names
 */
public class LayoutAlgorithmNames {
	//@formatter:off
	public static final String FORCED_BALANCED = "Force Balanced";
	public static final String FORCE_DIRECTED = "Force Directed";
	public static final String CIRCLE = "Circle";
	public static final String COMPACT_HIERARCHICAL = "Compact Hierarchical";
	public static final String COMPACT_RADIAL = "Compact Radial";
	public static final String MIN_CROSS_TOP_DOWN = "Hierarchical MinCross Top Down";
	public static final String MIN_CROSS_LONGEST_PATH = "Hierarchical MinCross Longest Path";
	public static final String MIN_CROSS_NETWORK_SIMPLEX = "Hierarchical MinCross Network Simplex";
	public static final String MIN_CROSS_COFFMAN_GRAHAM = "Hierarchical MinCross Coffman Graham";
	public static final String VERT_MIN_CROSS_TOP_DOWN = "Vertical Hierarchical MinCross Top Down";
	public static final String VERT_MIN_CROSS_LONGEST_PATH ="Vertical Hierarchical MinCross Longest Path";
	public static final String VERT_MIN_CROSS_NETWORK_SIMPLEX ="Vertical Hierarchical MinCross Network Simplex";
	public static final String VERT_MIN_CROSS_COFFMAN_GRAHAM ="Vertical Hierarchical MinCross Coffman Graham";
	public static final String HIERACHICAL = "Hierarchical";
	public static final String RADIAL = "Radial";
	public static final String BALLOON = "Balloon";
	public static final String GEM = "GEM";

	//@formatter:on

	public static List<String> getLayoutAlgorithmNames() {
		return Arrays.asList(COMPACT_HIERARCHICAL, HIERACHICAL,
			COMPACT_RADIAL, MIN_CROSS_TOP_DOWN, MIN_CROSS_LONGEST_PATH,
			MIN_CROSS_NETWORK_SIMPLEX, MIN_CROSS_COFFMAN_GRAHAM, CIRCLE,
			VERT_MIN_CROSS_TOP_DOWN,
			VERT_MIN_CROSS_LONGEST_PATH,
			VERT_MIN_CROSS_NETWORK_SIMPLEX,
			VERT_MIN_CROSS_COFFMAN_GRAHAM,
			FORCED_BALANCED, FORCE_DIRECTED, RADIAL, BALLOON, GEM);
	}
}
