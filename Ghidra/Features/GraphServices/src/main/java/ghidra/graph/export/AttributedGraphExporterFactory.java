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

import java.util.AbstractMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.jgrapht.nio.*;

import ghidra.service.graph.*;

/**
 * Specific implementation of {@link AbstractGraphExporterFactory} for exporting graphs with
 * {@link AttributedVertex} vertices and {@link AttributedEdge} edges.
 */
public class AttributedGraphExporterFactory
		extends AbstractGraphExporterFactory<AttributedVertex, AttributedEdge> {

	AttributedGraphExporterFactory() {
		vertexLabelProvider = AttributedVertex::getName;
		edgeLabelProvider = Object::toString;
		edgeIdProvider = e -> e.getId();
		edgeAttributeProvider = AttributedGraphExporterFactory::getComponentAttributes;
		vertexAttributeProvider = AttributedGraphExporterFactory::getComponentAttributes;
		vertexIdProvider = AttributedVertex::getId;
	}

	/**
	 * Gets {@link GraphExporter} configured to output a graph in the specified format.
	 * @param format the output file format.
	 * @return  {@link GraphExporter} configured to output a graph in the specified format.
	 */
	public static GraphExporter<AttributedVertex, AttributedEdge> getExporter(
			GraphExportFormat format) {
		return new AttributedGraphExporterFactory().createExporter(format);
	}

	private static Map<String, Attribute> getComponentAttributes(Attributed v) {
		return v.getAttributeMap()
				.entrySet()
				.stream()
				.map(entry -> new AbstractMap.SimpleEntry<String, Attribute>(entry.getKey(),
					new DefaultAttribute<String>(entry.getValue(), AttributeType.STRING)))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
	}
}
