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
//@__params_start
//@category C++
//@toolbar world.png
//@menupath Tools.Scripts Manager.Graph Classes Script
//@__params_end

import java.util.ArrayList;
import java.util.List;

import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.service.graph.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GraphClassesScript extends GhidraScript {

	private static final String NO_INHERITANCE = "No Inheritance";
	private static final String SINGLE_INHERITANCE = "Single Inheritance";
	private static final String MULTIPLE_INHERITANCE = "Multiple Inheritance";
	private static final String VIRTUAL_INHERITANCE = "Virtual Inheritance";
	private static final String NON_VIRTUAL_INHERITANCE = "Non-virtual Inheritance";

	List<Structure> classStructures = new ArrayList<>();

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
				"/ClassDataTypes folder does not exist so there is no class data to process. Please run the RecoverClassesFromRTTIScript to generate the necessary information needed to run this script.");
			return;
		}

		Category[] subCategories = category.getCategories();

		getClassStructures(subCategories);

		if (classStructures.isEmpty()) {
			println("There were no class structures to process.");
			return;
		}

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
			monitor.checkCancelled();
			DataType[] dataTypes = category.getDataTypes();
			for (DataType dataType : dataTypes) {
				monitor.checkCancelled();
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

	/**
	 * Method to create a graph using pre-configured information found in class structure 
	 * descriptions.
	 * @return the newly created graph
	 */
	private AttributedGraph createGraph() throws Exception {

		GraphType graphType =
			new GraphTypeBuilder("Class Hierarchy Graph").vertexType(NO_INHERITANCE)
					.vertexType(SINGLE_INHERITANCE)
					.vertexType(MULTIPLE_INHERITANCE)
					.edgeType(NON_VIRTUAL_INHERITANCE)
					.edgeType(VIRTUAL_INHERITANCE)
					.build();

		AttributedGraph g = new AttributedGraph("Recovered Classes Graph", graphType);

		for (Structure classStructure : classStructures) {

			monitor.checkCancelled();

			String description = classStructure.getDescription();

			// parse description for class hierarchy
			if (!description.startsWith("class")) {
				continue;
			}

			// skip "class " to get overall class
			description = description.substring(6);
			String mainClassName = getClassName(description);

			if (mainClassName == null || mainClassName.isBlank()) {
				continue;
			}

			AttributedVertex classVertex =
				g.addVertex(classStructure.getCategoryPath().getPath(), mainClassName);
			classVertex.setDescription(classStructure.getCategoryPath().getPath());

			int numParents = 0;
			description = removeClassSubstring(description, mainClassName);

			while (description != null) {

				numParents++;

				String parentName = getClassName(description);

				boolean isVirtualParent = false;
				if (parentName.contains("virtual")) {
					isVirtualParent = true;
				}

				parentName = parentName.replace("virtual", "");
				parentName = parentName.replace(" ", "");

				// first try to get parent structure from inside child structure
				Structure parentStructure =
					getParentStructureFromChildStructure(classStructure, parentName);

				// if parent structure isn't in child structure then try to get it by name
				// from the list of class structures - only returns one if unique
				if (parentStructure == null) {
					parentStructure = getParentStructureFromClassStructures(parentName);
				}

				AttributedVertex parentVertex;
				if (parentStructure == null) {
					parentVertex = g.addVertex(parentName);
					parentVertex.setDescription("Couldn't get parent structure " + parentName +
						" from structure " + classStructure.getName() +
						" or uniquely from all class structures");
					println("Couldn't get parent structure " + parentName + " from structure " +
						classStructure.getName() + " or uniquely from all class structures");
				}
				else {
					parentVertex =
						g.addVertex(parentStructure.getCategoryPath().getPath(), parentName);
					parentVertex.setDescription(parentStructure.getCategoryPath().getPath());
				}

				AttributedEdge edge = g.addEdge(parentVertex, classVertex);
				if (isVirtualParent) {
					edge.setEdgeType(VIRTUAL_INHERITANCE);
				}
				else {
					// else leave it default lime green
					edge.setEdgeType(NON_VIRTUAL_INHERITANCE);
				}

				description = removeClassSubstring(description, parentName);
			}

			// no parent = blue vertex
			if (numParents == 0) {
				classVertex.setVertexType(NO_INHERITANCE);
			}
			// single parent = green vertex
			else if (numParents == 1) {
				classVertex.setVertexType(SINGLE_INHERITANCE);
			}
			// multiple parents = red vertex
			else {
				classVertex.setVertexType(MULTIPLE_INHERITANCE);
			}
		}

		return g;
	}

	private String removeClassSubstring(String string, String substring) {

		int indexofSubstring = string.indexOf(substring);
		if (indexofSubstring == -1) {
			return null;
		}

		if (indexofSubstring + substring.length() >= string.length()) {
			return null;
		}

		String newString = string.substring(indexofSubstring + substring.length());
		if (newString.isBlank() || newString.isEmpty()) {
			return null;
		}

		// should be a space : space and another class name next if gets to here
		if (newString.length() < 4) {
			return null;
		}

		if (newString.indexOf(" : ") == 0) {
			return newString.substring(3);
		}

		return null;

	}

	private int getIndexOfFirstSingleColon(String string) {

		// replace all :: with something else so can isolate :'s 
		String testString = new String(string);
		testString = testString.replace("::", "xx");

		return testString.indexOf(":", 0);

	}

	/**
	 * Attempts to get the parent structure from within the child structure given the parent name
	 * @param childStructure the child structure
	 * @param parentName the name of the parent structure
	 * @return the parent structure or null if the parent structure is not contained in the child structure
	 * @throws CancelledException if cancelled
	 */
	private Structure getParentStructureFromChildStructure(Structure childStructure,
			String parentName)
			throws CancelledException {

		DataTypeComponent[] components = childStructure.getComponents();
		for (DataTypeComponent component : components) {

			monitor.checkCancelled();
			DataType componentDataType = component.getDataType();
			if (componentDataType instanceof Structure &&
				componentDataType.getName().equals(parentName)) {
				return (Structure) componentDataType;
			}
		}
		return null;
	}

	/**
	 * Attempts to get the parent structure from the list of class structures
	 * @param parentName the name of the parent
	 * @return the parent structure if there is only one with the given name, else returns null
	 * @throws CancelledException if cancelled
	 */
	private Structure getParentStructureFromClassStructures(String parentName)
			throws CancelledException {

		List<Structure> parentStructures = new ArrayList<>();
		for (Structure classStructure : classStructures) {
			monitor.checkCancelled();

			if (classStructure.getName().equals(parentName)) {
				parentStructures.add(classStructure);
			}

		}
		if (parentStructures.size() == 1) {
			return parentStructures.get(0);
		}
		return null;

	}

	private void showGraph(AttributedGraph graph) throws Exception {

		GraphDisplay display;
		PluginTool tool = state.getTool();
		GraphDisplayBroker broker = tool.getService(GraphDisplayBroker.class);
		GraphDisplayProvider service = broker.getGraphDisplayProvider("Default Graph Display");
		display = service.getGraphDisplay(false, TaskMonitor.DUMMY);

		GraphDisplayOptions graphOptions = new GraphDisplayOptionsBuilder(graph.getGraphType())
				.vertex(NO_INHERITANCE, VertexShape.RECTANGLE, Palette.BLUE)
				.vertex(SINGLE_INHERITANCE, VertexShape.RECTANGLE, Palette.GREEN)
				.vertex(MULTIPLE_INHERITANCE, VertexShape.RECTANGLE, Palette.RED)
				.edge(NON_VIRTUAL_INHERITANCE, Palette.LIME)
				.edge(VIRTUAL_INHERITANCE, Palette.ORANGE)
				.defaultVertexColor(Palette.PURPLE)
				.defaultEdgeColor(Palette.PURPLE)
				.defaultLayoutAlgorithm("Compact Hierarchical")
				.maxNodeCount(1000)
				.build();

		display.setGraph(graph, graphOptions,
			"Recovered Classes Graph", false, TaskMonitor.DUMMY);
	}

	private String getClassName(String description) {

		int indexOfColon = getIndexOfFirstSingleColon(description);
		String firstClassName;
		if (indexOfColon == -1) {
			firstClassName = description;
		}
		else {
			firstClassName = description.substring(0, indexOfColon - 1);
		}
		firstClassName = firstClassName.replace(" ", "");

		return firstClassName;
	}

}
