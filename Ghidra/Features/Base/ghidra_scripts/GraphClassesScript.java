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
//Script to graph class hierarchies given metadata found in class structure description that
// was applied using the RecoverClassesFromRTTIScript.  
//@category C++
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.service.graph.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GraphClassesScript extends GhidraScript {

	List<Structure> classStructures = new ArrayList<Structure>();

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("There is no open program");
			return;
		}

		DataTypeManager dataTypeManager = currentProgram.getDataTypeManager();

		String path = new String("ClassDataTypes");
		CategoryPath dataTypePath = new CategoryPath(CategoryPath.ROOT, path);

		Category category = dataTypeManager.getCategory(dataTypePath);
		if (category == null) {
			println(
				"/ClassDataTypes folder does not exist so there is no class data to process. Please run the ExtractClassInfoFromRTTIScript to generate the necessary information needed to run this script.");
			return;
		}

		Category[] subCategories = category.getCategories();

		getClassStructures(subCategories);

		AttributedGraph graph = createGraph();
		if (graph.getVertexCount() == 0) {
			println(
				"There was no metadata in the class structures so a graph could not be created. Please run the ExtractClassInfoFromRTTIScript to generate the necessary information needed to run this script.");
		}
		else {
			showGraph(graph);
		}

	}

	private void getClassStructures(Category[] categories) throws CancelledException {

		for (Category category : categories) {
			monitor.checkCanceled();
			DataType[] dataTypes = category.getDataTypes();
			for (DataType dataType : dataTypes) {
				monitor.checkCanceled();
				if (dataType.getName().equals(category.getName()) &&
					dataType instanceof Structure) {

					// if the data type name is the same as the folder name then
					// it is the main class structure
					Structure classStructure = (Structure) dataType;
					if (!classStructures.contains(classStructure)) {
						classStructures.add(classStructure);
					}

				}
			}

			Category[] subcategories = category.getCategories();

			if (subcategories.length > 0) {
				getClassStructures(subcategories);
			}
		}
	}

	private AttributedGraph createGraph() throws CancelledException {

		AttributedGraph g = new AttributedGraph();

		Iterator<Structure> classStructuresIterator = classStructures.iterator();
		while (classStructuresIterator.hasNext()) {

			monitor.checkCanceled();

			Structure classStructure = classStructuresIterator.next();

			String description = classStructure.getDescription();
			String mainClassName = getClassName(description);

			if (mainClassName == null) {
				continue;
			}

			AttributedVertex classVertex = g.addVertex(mainClassName);

			int numParents = 0;
			while (description.contains(":")) {

				numParents++;

				int indexOfColon = description.indexOf(":", 0);

				description = description.substring(indexOfColon + 1);

				int endOfBlock = description.indexOf(":", 0);
				if (endOfBlock == -1) {
					endOfBlock = description.length();
				}

				String parentName = description.substring(0, endOfBlock);

				description = description.substring(endOfBlock);

				boolean isVirtualParent = false;
				if (parentName.contains("virtual")) {
					isVirtualParent = true;
				}

				parentName = parentName.replace("virtual", "");
				parentName = parentName.replace(" ", "");


				AttributedVertex parentVertex = g.addVertex(parentName);

				AttributedEdge edge = g.addEdge(parentVertex, classVertex);
				if (isVirtualParent) {
					edge.setAttribute("Color", "Orange");
				}
				// else leave it default lime green
			}

			// no parent = blue vertex
			if (numParents == 0) {
				classVertex.setAttribute("Color", "Blue");
			}
			// single parent = green vertex
			else if (numParents == 1) {
				classVertex.setAttribute("Color", "Green");
			}
			// multiple parents = red vertex
			else {
				classVertex.setAttribute("Color", "Red");
			}
		}

		return g;
	}

	private void showGraph(AttributedGraph graph) throws Exception {

		GraphDisplay display;
		PluginTool tool = state.getTool();
		GraphDisplayBroker broker = tool.getService(GraphDisplayBroker.class);
		GraphDisplayProvider service = broker.getGraphDisplayProvider("Default Graph Display");
		display = service.getGraphDisplay(false, TaskMonitor.DUMMY);
		display.setGraph(graph, "test graph", false, TaskMonitor.DUMMY);
	}

	private String getClassName(String description) {

		// parse description for class hierarchy
		if (!description.startsWith("class")) {
			return null;
		}

		// skip "class " to get overall class
		description = description.substring(6);
		int indexOfColon = description.indexOf(":", 0);
		String mainClassName;
		if (indexOfColon == -1) {
			mainClassName = description;
		}
		else {
			mainClassName = description.substring(0, indexOfColon - 1);
		}
		mainClassName = mainClassName.replace(" ", "");

		return mainClassName;
	}

}
