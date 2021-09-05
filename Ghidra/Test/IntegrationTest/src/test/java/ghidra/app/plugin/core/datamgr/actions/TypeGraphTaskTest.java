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
package ghidra.app.plugin.core.datamgr.actions;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.graph.TestGraphDisplay;
import ghidra.graph.TestGraphService;
import ghidra.program.model.data.*;
import ghidra.service.graph.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.GraphException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class TypeGraphTaskTest extends AbstractGhidraHeadedIntegrationTest {

	private Structure base;
	private Structure other;
	private Pointer pointer;
	private Pointer otherPointer;
	private TypeDef otherTypeDef;
	private TestGraphService graphService;

	@Before
	public void setUp() throws Exception {
		base = new StructureDataType("base structure", 16);
		base.insert(0, new IntegerDataType());

		other = new StructureDataType("another struct", 20);
		other.insert(0, new IntegerDataType());
		other.insert(1, new FloatDataType());

		pointer = new PointerDataType(new IntegerDataType());
		otherPointer = new PointerDataType(other);

		otherTypeDef = new TypedefDataType("other_t", other);

		graphService = new TestGraphService();

	}

	@Test
	public void testSimpleStructure() throws GraphException {
		Task task = new TypeGraphTask(base, graphService);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		AttributedGraph graph = display.getGraph();

		assertEquals(1, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(base.getName());
		assertNotNull(v1);
	}

	@Test
	public void testNestedStructure() throws GraphException {
		base.insert(1, other);
		Task task = new TypeGraphTask(base, graphService);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		AttributedGraph graph = display.getGraph();

		assertEquals(2, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(base.getName());
		assertNotNull(v1);
		AttributedVertex v2 = graph.getVertex(other.getName());
		assertNotNull(v2);
		AttributedEdge e1 = graph.getEdge(v1, v2);
		assertNotNull(e1);
		assertEquals(TypeGraphTask.COMPOSITE, e1.getEdgeType());
	}

	@Test
	public void testStructureWithPointer() throws GraphException {
		base.insert(1, pointer);
		Task task = new TypeGraphTask(base, graphService);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		AttributedGraph graph = display.getGraph();

		assertEquals(1, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(base.getName());
		assertNotNull(v1);
	}

	@Test
	public void testPointerToStructure() throws GraphException {
		base.insert(1, otherPointer);
		Task task = new TypeGraphTask(base, graphService);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		AttributedGraph graph = display.getGraph();

		assertEquals(2, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(base.getName());
		assertNotNull(v1);
		AttributedVertex v2 = graph.getVertex(other.getName());
		assertNotNull(v2);
		AttributedEdge e1 = graph.getEdge(v1, v2);
		assertNotNull(e1);
		assertEquals(TypeGraphTask.REFERENCE, e1.getEdgeType());
	}

	@Test
	public void testEmbeddedAndPointer() throws GraphException {
		base.insert(1, other);
		base.insert(2, pointer);
		Task task = new TypeGraphTask(base, graphService);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		AttributedGraph graph = display.getGraph();

		assertEquals(2, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(base.getName());
		assertNotNull(v1);
		AttributedVertex v2 = graph.getVertex(other.getName());
		assertNotNull(v2);
		AttributedEdge e1 = graph.getEdge(v1, v2);
		assertNotNull(e1);
		assertEquals(TypeGraphTask.COMPOSITE, e1.getEdgeType());
	}

	@Test
	public void testPointerToPointer() throws GraphException {
		Pointer pointerToPointer = new PointerDataType(otherPointer);
		base.insert(1, pointerToPointer);
		Task task = new TypeGraphTask(base, graphService);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		AttributedGraph graph = display.getGraph();

		assertEquals(2, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(base.getName());
		assertNotNull(v1);
		AttributedVertex v2 = graph.getVertex(other.getName());
		assertNotNull(v2);
		AttributedEdge e1 = graph.getEdge(v1, v2);
		assertNotNull(e1);
		assertEquals(TypeGraphTask.REFERENCE, e1.getEdgeType());
	}

	@Test
	public void testEmbeddedTypedef() throws GraphException {
		base.insert(1, otherTypeDef);
		Task task = new TypeGraphTask(base, graphService);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		AttributedGraph graph = display.getGraph();

		assertEquals(2, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(base.getName());
		assertNotNull(v1);
		AttributedVertex v2 = graph.getVertex(other.getName());
		assertNotNull(v2);
		AttributedEdge e1 = graph.getEdge(v1, v2);
		assertNotNull(e1);
		assertEquals(TypeGraphTask.COMPOSITE, e1.getEdgeType());
	}

	@Test
	public void testPointerToTypedef() throws GraphException {
		Pointer typedefPtr = new PointerDataType(otherTypeDef);
		base.insert(1, typedefPtr);
		Task task = new TypeGraphTask(base, graphService);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		AttributedGraph graph = display.getGraph();

		assertEquals(2, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(base.getName());
		assertNotNull(v1);
		AttributedVertex v2 = graph.getVertex(other.getName());
		assertNotNull(v2);
		AttributedEdge e1 = graph.getEdge(v1, v2);
		assertNotNull(e1);
		assertEquals(TypeGraphTask.REFERENCE, e1.getEdgeType());
	}

	@Test
	public void testPointerToSelf() throws GraphException {
		Pointer selfPtr = new PointerDataType(base);
		base.insert(1, selfPtr);
		Task task = new TypeGraphTask(base, graphService);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		AttributedGraph graph = display.getGraph();

		assertEquals(1, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(base.getName());
		assertNotNull(v1);
		AttributedEdge e1 = graph.getEdge(v1, v1);
		assertNotNull(e1);
	}

	@Test
	public void testPointerCycle() throws GraphException {
		base.insert(1, otherPointer);
		Pointer basePtr = new PointerDataType(base);
		other.insert(1, basePtr);
		Task task = new TypeGraphTask(base, graphService);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		AttributedGraph graph = display.getGraph();

		assertEquals(2, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(base.getName());
		assertNotNull(v1);
		AttributedVertex v2 = graph.getVertex(other.getName());
		assertNotNull(v2);
		AttributedEdge e1 = graph.getEdge(v1, v2);
		assertNotNull(e1);
		AttributedEdge e2 = graph.getEdge(v2, v1);
		assertNotNull(e2);
	}
}
