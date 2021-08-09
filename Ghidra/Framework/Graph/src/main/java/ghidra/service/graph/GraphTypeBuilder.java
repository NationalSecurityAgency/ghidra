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

import java.util.ArrayList;
import java.util.List;

/**
 * Builder class for building new {@link GraphType}s
 */
public class GraphTypeBuilder {
	private List<String> vertexTypes = new ArrayList<>();
	private List<String> edgeTypes = new ArrayList<>();
	private final String name;
	private String description;

	/**
	 * Create a new builder
	 * @param name the name of the new {@link GraphType}
	 */
	public GraphTypeBuilder(String name) {
		this.name = name;
		this.description = name;
	}

	/**
	 * Sets the description for the {@link GraphType}
	 * @param text the description
	 * @return this GraphTypeBuilder
	 */
	public GraphTypeBuilder description(String text) {
		this.description = text;
		return this;
	}

	/**
	 * Defines a new vertex type
	 * @param type a string that names a new vertex type
	 * @return this GraphTypeBuilder
	 */
	public GraphTypeBuilder vertexType(String type) {
		vertexTypes.add(type);
		return this;
	}

	/**
	 * Defines a new edge type
	 * @param type a string that names a new edge type
	 * @return this GraphTypeBuilder
	 */
	public GraphTypeBuilder edgeType(String type) {
		edgeTypes.add(type);
		return this;
	}

	/**
	 * Builds a new GraphType
	 * @return a new GraphType
	 */
	public GraphType build() {
		return new GraphType(name, description, vertexTypes, edgeTypes);
	}
}
