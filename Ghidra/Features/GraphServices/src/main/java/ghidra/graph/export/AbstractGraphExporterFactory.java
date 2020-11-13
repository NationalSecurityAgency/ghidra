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
package ghidra.graph.export;

import java.util.Collections;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

import org.jgrapht.nio.*;
import org.jgrapht.nio.csv.*;
import org.jgrapht.nio.dimacs.DIMACSExporter;
import org.jgrapht.nio.dimacs.DIMACSFormat;
import org.jgrapht.nio.dot.DOTExporter;
import org.jgrapht.nio.gml.GmlExporter;
import org.jgrapht.nio.graphml.GraphMLExporter;
import org.jgrapht.nio.json.JSONExporter;
import org.jgrapht.nio.lemon.LemonExporter;
import org.jgrapht.nio.matrix.MatrixExporter;

/**
 * Base factory class for using the JGrapht export library.  Clients should subclass this
 * for specific graph types and provide better providers than the defaults defined here.
 *
 * @param <V> the graph vertex type
 * @param <E> the graph edge type
 */
public abstract class AbstractGraphExporterFactory<V, E> {
	protected char csvDelimiter = ',';
	protected CSVFormat csvFormat = CSVFormat.EDGE_LIST;
	protected DIMACSFormat dimacsFormat = DIMACSExporter.DEFAULT_DIMACS_FORMAT;
	protected MatrixExporter.Format matrixFormat = MatrixExporter.Format.SPARSE_ADJACENCY_MATRIX;

	protected Function<V, String> defaultVertexIdProvider = new IntegerIdProvider<>();
	protected Function<E, String> defaultEdgeIdProvider = new IntegerIdProvider<>();

	protected Supplier<String> graphIdProvider = () -> "Ghidra";
	protected Function<V, String> vertexLabelProvider = Object::toString;
	protected Function<E, String> edgeLabelProvider = Object::toString;
	protected Function<E, String> edgeIdProvider = defaultEdgeIdProvider;
	protected Function<V, String> vertexIdProvider = defaultVertexIdProvider;

	protected Function<E, Map<String, Attribute>> edgeAttributeProvider =
		e -> Collections.emptyMap();
	protected Function<V, Map<String, Attribute>> vertexAttributeProvider =
		v -> Collections.emptyMap();

	/**
	 * Creates an exporter of the specified type
	 * 
	 * @param format the file output type
	 * @return a {@link GraphExporter} configured to output in the specified format
	 */
	public GraphExporter<V, E> createExporter(GraphExportFormat format) {
		switch (format) {
			case CSV:
				return createCsvExporter();
			case DIMACS:
				return createDimacsExporter();
			case DOT:
				return createDotExporter();
			case GML:
				return createGmlExporter();
			case JSON:
				return createJsonExporter();
			case LEMON:
				return createLemonExporter();
			case MATRIX:
				return createMatrixExporter();
			case VISIO:
				return createVisioExporter();
			case GRAPHML:
			default:
				return createGraphMlExporter();

		}
	}

	private GraphExporter<V, E> createGraphMlExporter() {
		GraphMLExporter<V, E> exporter = new GraphMLExporter<>(vertexIdProvider);
		setupExporter(exporter);
		return exporter;
	}

	private GraphExporter<V, E> createVisioExporter() {
		VisioExporter<V, E> exporter = new VisioExporter<>(vertexIdProvider);
		setupExporter(exporter);
		return exporter;
	}

	private GraphExporter<V, E> createMatrixExporter() {
		MatrixExporter<V, E> exporter = new MatrixExporter<>(matrixFormat, vertexIdProvider);
		setupExporter(exporter);
		return exporter;
	}

	private GraphExporter<V, E> createLemonExporter() {
		LemonExporter<V, E> exporter = new LemonExporter<>(vertexIdProvider);
		setupExporter(exporter);
		return exporter;
	}

	private GraphExporter<V, E> createJsonExporter() {
		JSONExporter<V, E> exporter = new JSONExporter<>(vertexIdProvider);
		setupExporter(exporter);
		return exporter;
	}

	private GraphExporter<V, E> createGmlExporter() {
		GmlExporter<V, E> exporter = new GmlExporter<>(vertexIdProvider);
		setupExporter(exporter);
		return exporter;
	}

	private GraphExporter<V, E> createDotExporter() {
		DOTExporter<V, E> exporter = new DOTExporter<>(vertexIdProvider);
		setupExporter(exporter);
		return exporter;
	}

	private GraphExporter<V, E> createDimacsExporter() {
		DIMACSExporter<V, E> exporter = new DIMACSExporter<>(vertexIdProvider, dimacsFormat);
		setupExporter(exporter);
		return exporter;
	}

	private GraphExporter<V, E> createCsvExporter() {
		CSVExporter<V, E> exporter = new CSVExporter<>(vertexIdProvider, csvFormat, csvDelimiter);
		setupExporter(exporter);
		return exporter;
	}

	private void setupExporter(BaseExporter<V, E> exporter) {
		exporter.setEdgeIdProvider(defaultEdgeIdProvider);
		exporter.setVertexAttributeProvider(vertexAttributeProvider);
		exporter.setEdgeAttributeProvider(edgeAttributeProvider);
		exporter.setGraphIdProvider(graphIdProvider);
	}
}
