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

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.graph.exporter.*;
import ghidra.service.graph.*;
import ghidra.util.Msg;
import utilities.util.FileUtilities;

public class AttributedGraphExportersTest extends AbstractGenericTest {

	private AttributedGraph graph;

	@Before
	public void setUp() throws Exception {

		graph = createGraph();
	}

	@After
	public void tearDown() {
	}

	@Test
	public void testCsvEdgeList() throws Exception {
		CsvEdgeListGraphExporter exporter = new CsvEdgeListGraphExporter();
		List<String> lines = doExport(exporter, graph);

		assertOutput(lines,
			"A,B",
			"B,C",
			"B,D",
			"C,E",
			"D,E");
	}

	@Test
	public void testCsvAdjacencyList() throws Exception {
		CsvAdjacencyListGraphExporter exporter = new CsvAdjacencyListGraphExporter();
		List<String> lines = doExport(exporter, graph);

		assertOutput(lines,
			"A,B",
			"B,C,D",
			"C,E",
			"D,E",
			"E",
			"F");
	}

	@Test
	public void testDIMACS() throws Exception {
		DimacsGraphExporter exporter = new DimacsGraphExporter();
		List<String> lines = doExport(exporter, graph);
		assertOutput(lines,
			"c",
			"c SOURCE: Generated using the JGraphT library",
			"c",
			"p edge 6 5",
			"e A B",
			"e B C",
			"e B D",
			"e C E",
			"e D E");
	}

	@Test
	public void testDOT() throws Exception {
		DotGraphExporter exporter = new DotGraphExporter();
		List<String> lines = doExport(exporter, graph);

		assertOutput(lines,
			"digraph Ghidra {",
			"  \"A\" [ Type=\"X\" Inverted=\"true\" Name=\"A\" ];",
			"  \"B\" [ Type=\"Y\" Name=\"B\" ];",
			"  \"C\" [ Type=\"Y\" Name=\"C\" ];",
			"  \"D\" [ Type=\"Y\" Name=\"D\" ];",
			"  \"E\" [ Type=\"Z\" Name=\"E\" ];",
			"  \"F\" [ Type=\"T\" Name=\"F\" ];",
			"  \"A\" -> \"B\" [ EType=\"Fall\" ];",
			"  \"B\" -> \"C\" [ EType=\"JMP\" ];",
			"  \"B\" -> \"D\" [ EType=\"Fall\" ];",
			"  \"C\" -> \"E\" [ EType=\"Fall\" ];",
			"  \"D\" -> \"E\" [ EType=\"Call\" ];",
			"}");

	}

	@Test
	public void testGraphML() throws Exception {
		GmlGraphExporter exporter = new GmlGraphExporter();
		List<String> lines = doExport(exporter, graph);
		assertOutput(lines,
			"Creator \"JGraphT GML Exporter\"",
			"Version 1",
			"graph",
			"[",
			"	label \"\"",
			"	directed 1",
			"	node",
			"	[",
			"		id A",
			"	]",
			"	node",
			"	[",
			"		id B",
			"	]",
			"	node",
			"	[",
			"		id C",
			"	]",
			"	node",
			"	[",
			"		id D",
			"	]",
			"	node",
			"	[",
			"		id E",
			"	]",
			"	node",
			"	[",
			"		id F",
			"	]",
			"	edge",
			"	[",
			"		id 1",
			"		source A",
			"		target B",
			"	]",
			"	edge",
			"	[",
			"		id 2",
			"		source B",
			"		target C",
			"	]",
			"	edge",
			"	[",
			"		id 3",
			"		source B",
			"		target D",
			"	]",
			"	edge",
			"	[",
			"		id 4",
			"		source C",
			"		target E",
			"	]",
			"	edge",
			"	[",
			"		id 5",
			"		source D",
			"		target E",
			"	]",
			"]");
	}

	@Test
	public void testGRAPHML() throws Exception {
		GraphMlGraphExporter exporter = new GraphMlGraphExporter();
		List<String> lines = doExport(exporter, graph);
		assertOutput(lines,
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?><graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\" xsi:schemaLocation=\"http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">", 
			"    <key id=\"key11\" for=\"node\" attr.name=\"Type\" attr.type=\"string\"/>",
			"    <key id=\"key1\" for=\"node\" attr.name=\"Inverted\" attr.type=\"string\"/>", 
			"    <key id=\"key12\" for=\"node\" attr.name=\"Name\" attr.type=\"string\"/>",
			"    <key id=\"key17\" for=\"edge\" attr.name=\"EType\" attr.type=\"string\"/>",
			"    <graph edgedefault=\"directed\">", 
			"        <node id=\"A\">", 
			"            <data key=\"key11\">X</data>",
			"            <data key=\"key1\">true</data>", 
			"            <data key=\"key12\">A</data>",
			"        </node>", 
			"        <node id=\"B\">", 
			"            <data key=\"key11\">Y</data>", "            <data key=\"key12\">B</data>",
			"        </node>", 
			"        <node id=\"C\">", 
			"            <data key=\"key11\">Y</data>", "            <data key=\"key12\">C</data>",
			"        </node>", 
			"        <node id=\"D\">", 
			"            <data key=\"key11\">Y</data>", "            <data key=\"key12\">D</data>",
			"        </node>", 
			"        <node id=\"E\">", 
			"            <data key=\"key11\">Z</data>", "            <data key=\"key12\">E</data>",
			"        </node>", "        <node id=\"F\">",
			"            <data key=\"key11\">T</data>", "            <data key=\"key12\">F</data>",
			"        </node>", 
			"        <edge id=\"1\" source=\"A\" target=\"B\">", 
			"            <data key=\"key17\">Fall</data>",
			"        </edge>", 
			"        <edge id=\"2\" source=\"B\" target=\"C\">", 
			"            <data key=\"key17\">JMP</data>",
			"        </edge>", 
			"        <edge id=\"3\" source=\"B\" target=\"D\">", 
			"            <data key=\"key17\">Fall</data>",
			"        </edge>", 
			"        <edge id=\"4\" source=\"C\" target=\"E\">", 
			"            <data key=\"key17\">Fall</data>",
			"        </edge>", 
			"        <edge id=\"5\" source=\"D\" target=\"E\">", 
			"            <data key=\"key17\">Call</data>",
			"        </edge>", 
			"    </graph>", 
			"</graphml>");

	}

	@Test
	public void testJSON() throws Exception {
		JsonGraphExporter exporter = new JsonGraphExporter();
		List<String> lines = doExport(exporter, graph);
		assertOutput(lines,
			"{\"creator\":\"JGraphT JSON Exporter\",\"version\":\"1\",\"nodes\":" +
				"[{\"id\":\"A\",\"Type\":\"X\",\"Inverted\":\"true\",\"Name\":\"A\"}," +
				"{\"id\":\"B\",\"Type\":\"Y\",\"Name\":\"B\"}," +
				"{\"id\":\"C\",\"Type\":\"Y\",\"Name\":\"C\"}," +
				"{\"id\":\"D\",\"Type\":\"Y\",\"Name\":\"D\"}," +
				"{\"id\":\"E\",\"Type\":\"Z\",\"Name\":\"E\"}," +
				"{\"id\":\"F\",\"Type\":\"T\",\"Name\":\"F\"}]," +
				"\"edges\":[{\"id\":\"1\",\"source\":\"A\",\"target\":\"B\",\"EType\":\"Fall\"}," +
				"{\"id\":\"2\",\"source\":\"B\",\"target\":\"C\",\"EType\":\"JMP\"}," +
				"{\"id\":\"3\",\"source\":\"B\",\"target\":\"D\",\"EType\":\"Fall\"}," +
				"{\"id\":\"4\",\"source\":\"C\",\"target\":\"E\",\"EType\":\"Fall\"}," +
				"{\"id\":\"5\",\"source\":\"D\",\"target\":\"E\",\"EType\":\"Call\"}]}");

	}

	@Test
	public void testMATRIX() throws Exception {
		MatrixGraphExporter exporter = new MatrixGraphExporter();
		List<String> lines = doExport(exporter, graph);
		assertOutput(lines,
			"A B 1",
			"B C 1",
			"B D 1",
			"C E 1",
			"D E 1");
	}

	@Test
	public void testVISIO() throws Exception {
		VisioGraphExporter exporter = new VisioGraphExporter();
		List<String> lines = doExport(exporter, graph);
		assertOutput(lines,
			"Shape,A,,A",
			"Shape,B,,B",
			"Shape,C,,C",
			"Shape,D,,D",
			"Shape,E,,E",
			"Shape,F,,F",
			"Link,A-->B,,,A,B",
			"Link,B-->C,,,B,C",
			"Link,B-->D,,,B,D",
			"Link,C-->E,,,C,E",
			"Link,D-->E,,,D,E");
	}

	private AttributedGraph createGraph() {
		AttributedGraph g = new AttributedGraph("Test", new EmptyGraphType());
		AttributedVertex vA = g.addVertex("A");
		AttributedVertex vB = g.addVertex("B");
		AttributedVertex vC = g.addVertex("C");
		AttributedVertex vD = g.addVertex("D");
		AttributedVertex vE = g.addVertex("E");
		AttributedVertex vF = g.addVertex("F");

		//		A			
		//		|
		//	    B
		//     / \
		//    C   D     F
		//    \  /
		//      E

		AttributedEdge e1 = g.addEdge(vA, vB);
		AttributedEdge e2 = g.addEdge(vB, vC);
		AttributedEdge e3 = g.addEdge(vB, vD);
		AttributedEdge e4 = g.addEdge(vC, vE);
		AttributedEdge e5 = g.addEdge(vD, vE);

		vA.setAttribute("Type", "X");
		vB.setAttribute("Type", "Y");
		vC.setAttribute("Type", "Y");
		vD.setAttribute("Type", "Y");
		vE.setAttribute("Type", "Z");
		vF.setAttribute("Type", "T");

		e1.setAttribute("EType", "Fall");
		e2.setAttribute("EType", "JMP");
		e3.setAttribute("EType", "Fall");
		e4.setAttribute("EType", "Fall");
		e5.setAttribute("EType", "Call");

		vA.setAttribute("Inverted", "true");
		return g;
	}

	private void printLines(List<String> lines) {
		Msg.debug(this, "\n" + testName.getMethodName());
		for (String line : lines) {
			Msg.debug(this, "\"" + line + "\",");
		}
	}

	private void assertOutput(List<String> actual, String... expected) {
		assertEquals(expected.length, actual.size());
		try {
			for (int i = 0; i < expected.length; i++) {
				if (i >= actual.size()) {
					fail(testName.getMethodName() + ": output line " + (i + 1) + ": expected :\"" +
						expected[i] +
						"\", got: EOF");
				}
				assertEquals(testName.getMethodName() + ": output line " + (i + 1) + ": ",
					expected[i],
					actual.get(i));
			}
		}
		catch (Throwable e) {
			printLines(actual);
			throw e;
		}
	}

	private List<String> doExport(AttributedGraphExporter exporter, AttributedGraph graph2)
			throws IOException {
		File file = createTempFile("GraphTest", "." + exporter.getFileExtension());
		exporter.exportGraph(graph, file);
		List<String> lines = FileUtilities.getLines(file);
		return lines;
	}

}
