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
package ghidra.graph;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import ghidra.graph.graphs.FilteredVisualGraphTest;
import ghidra.graph.job.VisualGraphJobRunnerTest;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.edge.VisualGraphPathHighlighterTest;
import ghidra.graph.viewer.layout.GridLocationMapTest;

//@formatter:off
@RunWith(Suite.class)
@SuiteClasses({
	GraphViewerTransformationsTest.class,
	VisualGraphPathHighlighterTest.class,
	VisualGraphViewUpdaterTest.class,
	GraphViewerTest.class,
	GraphComponentTest.class,
	GridLocationMapTest.class,
	VisualGraphViewTest.class,
	FilteredVisualGraphTest.class,
	VisualGraphJobRunnerTest.class,  // this is headless; run last to avoid environment conflicts
	
	// in Base, can't reference
	// VisualGraphComponentProviderTest.class,
})
/** A suite useful for running all related tests and determining code coverage */
public class VisualGraphTestSuite {
	// in the annotation
}
