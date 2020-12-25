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
package ghidra.graph.exporter;

import java.io.File;
import java.io.IOException;

import org.jgrapht.nio.csv.VisioExporter;

import ghidra.service.graph.*;

public class VisioGraphExporter extends AbstractAttributedGraphExporter {

	@Override
	public void exportGraph(AttributedGraph graph, File file) throws IOException {
		VisioExporter<AttributedVertex, AttributedEdge> exporter =
			new VisioExporter<>(vertexIdProvider);

		try {
			exporter.exportGraph(graph, file);
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	public String getFileExtension() {
		return "vsd";
	}

	@Override
	public String getName() {
		return "VISIO";
	}

	@Override
	public String getDesciption() {
		return "JGraphT library export of a graph to a VISIO file";
	}

}
