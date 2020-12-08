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

import java.io.File;
import java.io.IOException;

import ghidra.util.classfinder.ExtensionPoint;

/**
 * Interface for exporting AttributedGraphs
 */
public interface AttributedGraphExporter extends ExtensionPoint {
	/**
	 * Exports the given graph to the given writer
	 * @param graph the {@link AttributedGraph} to export
	 * @param file the file to export to
	 * @throws IOException if there is an error exporting the graph
	 */
	public void exportGraph(AttributedGraph graph, File file) throws IOException;

	/**
	 * Returns the suggested file extension to use for this exporter
	 * @return the suggested file extension to use for this exporter
	 */
	public String getFileExtension();

	/**
	 * Returns the name of this exporter
	 * @return the name of this exporter
	 */
	public String getName();

	/**
	 * Returns a description of the exporter
	 * @return a description of the exporter
	 */
	public String getDesciption();

}
