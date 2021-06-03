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

import org.jgrapht.nio.dimacs.DIMACSExporter;
import org.jgrapht.nio.dimacs.DIMACSFormat;
import org.jgrapht.nio.dot.DOTExporter;

import ghidra.service.graph.*;

public class DotGraphExporter extends AbstractAttributedGraphExporter {

	protected DIMACSFormat dimacsFormat = DIMACSExporter.DEFAULT_DIMACS_FORMAT;


	@Override
	public void exportGraph(AttributedGraph graph, File file) throws IOException {
		DOTExporter<AttributedVertex, AttributedEdge> exporter =
			new DOTExporter<>(this::getQuotedId);

		exporter.setVertexAttributeProvider(this::getAttributes);
		exporter.setEdgeAttributeProvider(this::getAttributes);
		exporter.setGraphIdProvider(graphIdProvider);

		try {
			exporter.exportGraph(graph, file);
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	public String getFileExtension() {
		return "gf";
	}

	@Override
	public String getName() {
		return "DOT";
	}

	@Override
	public String getDesciption() {
		return "JGraphT library export of a graph to a DOT file";
	}

	String getQuotedId(AttributedVertex vertex) {
		String id = vertexIdProvider.apply(vertex);
		return "\"" + id + "\"";
	}
}
