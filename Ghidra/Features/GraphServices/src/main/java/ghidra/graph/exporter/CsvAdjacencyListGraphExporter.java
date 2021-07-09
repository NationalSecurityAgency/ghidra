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

import org.jgrapht.nio.csv.CSVExporter;
import org.jgrapht.nio.csv.CSVFormat;

import ghidra.service.graph.*;

public class CsvAdjacencyListGraphExporter extends AbstractAttributedGraphExporter {

	private static final char CVS_DELIMITER = ',';

	@Override
	public void exportGraph(AttributedGraph graph, File file) throws IOException {
		CSVExporter<AttributedVertex, AttributedEdge> exporter =
			new CSVExporter<>(vertexIdProvider, CSVFormat.ADJACENCY_LIST, CVS_DELIMITER);

		try {
			exporter.exportGraph(graph, file);
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	public String getFileExtension() {
		return "csv";
	}

	@Override
	public String getName() {
		return "CSV:Adjacency List";
	}

	@Override
	public String getDesciption() {
		return "JGraphT library export of a graph to a adjacency list CSV file";
	}

}
