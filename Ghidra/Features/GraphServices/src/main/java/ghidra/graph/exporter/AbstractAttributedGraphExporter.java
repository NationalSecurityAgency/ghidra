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

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.function.Supplier;

import org.jgrapht.nio.*;

import ghidra.service.graph.*;

/**
 * Abstract base class that graph exporters can extend to get some common functionality
 */
public abstract class AbstractAttributedGraphExporter implements AttributedGraphExporter {
	protected Function<AttributedEdge, String> edgeIdProvider = AttributedEdge::getId;
	protected Function<AttributedVertex, String> vertexIdProvider = AttributedVertex::getId;
	protected Supplier<String> graphIdProvider = () -> "Ghidra";

	/**
	 * Converts the attributes of an Attributed object from map of <String, String> to a 
	 * map of <String, Attribute>
	 * @param attributed the {@link Attributed} object 
	 * @return a map of <String, Attributes> that represent the attributes of the given Attributed
	 * object
	 */
	protected Map<String, Attribute> getAttributes(Attributed attributed) {
		Map<String, Attribute> attributeMap = new HashMap<>();

		for (Entry<String, String> entry :  attributed.entrySet()) {
			String key = entry.getKey();
			String value = entry.getValue();
			attributeMap.put(key, new DefaultAttribute<>(value, AttributeType.STRING));
		}
		return attributeMap;
	}

	@Override
	public String toString() {
		return getName();
	}

	@Override
	public int hashCode() {
		return getName().hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		AbstractAttributedGraphExporter other = (AbstractAttributedGraphExporter) obj;
		return getName().equals(other.getName());
	}

}
