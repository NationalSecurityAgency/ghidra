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

import ghidra.service.graph.*;

public class DimacsGraphExporter extends AbstractAttributedGraphExporter {

	protected DIMACSFormat dimacsFormat = DIMACSExporter.DEFAULT_DIMACS_FORMAT;


	@Override
	public void exportGraph(AttributedGraph graph, File file) throws IOException {
		DIMACSExporter<AttributedVertex, AttributedEdge> exporter =
			new DIMACSExporter<>(vertexIdProvider, dimacsFormat);

		try {
			exporter.exportGraph(graph, file);
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	public String getFileExtension() {
		return "col";
	}

	@Override
	public String getName() {
		return "DIMACS";
	}

	@Override
	public String getDesciption() {
		return "JGraphT library export of a graph to a DIMACS file";
	}

}
