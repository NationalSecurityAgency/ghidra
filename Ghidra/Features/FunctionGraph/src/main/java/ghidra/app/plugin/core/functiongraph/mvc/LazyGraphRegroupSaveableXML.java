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
package ghidra.app.plugin.core.functiongraph.mvc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collection;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.output.XMLOutputter;

import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupHistoryInfo;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupVertexSerializer;
import ghidra.util.Msg;
import ghidra.util.ObjectStorage;
import ghidra.util.xml.GenericXMLOutputter;

public class LazyGraphRegroupSaveableXML extends LazySaveableXML {

	private FunctionGraph functionGraph;

	public LazyGraphRegroupSaveableXML(FunctionGraph functionGraph) {
		this.functionGraph = functionGraph;
	}

	@Override
	public boolean isEmpty() {
		Collection<GroupHistoryInfo> groupHistory = functionGraph.getGroupHistory();
		return groupHistory.isEmpty();
	}

	@Override
	/**
	 * Overridden to create the {@link Element} to save at the time saving is taking place, 
	 * instead of construction time.
	 * 
	 * @param objStorage The object into which the data will be placed.
	 */
	public void save(ObjectStorage objStorage) {
		Element groupVertexElement =
			GroupVertexSerializer.getXMLForRegroupableVertices(functionGraph);
		Document document = new Document(groupVertexElement);
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		XMLOutputter xmlOutputter = new GenericXMLOutputter();

		try {
			xmlOutputter.output(document, outputStream);
		}
		catch (IOException ioe) {
			// shouldn't happen, as we are using our output stream
			Msg.error(getClass(), "Unable to save XML data.", ioe);
			return;
		}

		String xmlString = outputStream.toString();
		objStorage.putString(xmlString);
	}
}
