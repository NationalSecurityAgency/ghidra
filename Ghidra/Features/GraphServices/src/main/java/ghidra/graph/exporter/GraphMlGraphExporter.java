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
import java.util.Map;
import java.util.stream.Collectors;

import org.jgrapht.nio.AttributeType;
import org.jgrapht.nio.DefaultAttribute;
import org.jgrapht.nio.graphml.GraphMLExporter;

import ghidra.service.graph.*;

public class GraphMlGraphExporter extends AbstractAttributedGraphExporter {

	@Override
	public void exportGraph(AttributedGraph graph, File file) throws IOException {
		GraphMLExporter<AttributedVertex, AttributedEdge> exporter =
				new GraphMLExporter<>(vertexIdProvider);

		exporter.setEdgeIdProvider(edgeIdProvider);
		exporter.setVertexAttributeProvider(
				vertex -> vertex.entrySet()
						.stream()
						.collect(
								Collectors.toMap(
										Map.Entry::getKey,
										entry -> new DefaultAttribute(entry.getValue(), AttributeType.STRING))));
		exporter.setEdgeAttributeProvider(
				edge -> edge.entrySet()
						.stream()
						.collect(
								Collectors.toMap(
										Map.Entry::getKey,
										entry -> new DefaultAttribute<>(entry.getValue(), AttributeType.STRING))));

		graph.vertexSet().stream()
				.map(Attributed::getAttributeMap)
				.flatMap(m -> m.entrySet().stream())
				.map(Map.Entry::getKey)
				.forEach(key -> exporter.registerAttribute(key, GraphMLExporter.AttributeCategory.NODE, AttributeType.STRING));

		graph.edgeSet().stream()
				.map(Attributed::getAttributeMap)
				.flatMap(m -> m.entrySet().stream())
				.map(Map.Entry::getKey)
				.forEach(key -> exporter.registerAttribute(key, GraphMLExporter.AttributeCategory.EDGE, AttributeType.STRING));

		try {
			exporter.exportGraph(graph, file);
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	public String getFileExtension() {
		return "graphml";
	}

	@Override
	public String getName() {
		return "GRAPHML";
	}

	@Override
	public String getDesciption() {
		return "JGraphT library export of a graph to a GRAPHML file";
	}

}
