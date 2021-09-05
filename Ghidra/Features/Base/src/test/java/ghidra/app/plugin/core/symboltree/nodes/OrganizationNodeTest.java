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
package ghidra.app.plugin.core.symboltree.nodes;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.tree.GTreeNode;
import ghidra.program.model.symbol.StubSymbol;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Swing;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class OrganizationNodeTest extends AbstractDockingTest {

	@Test
	public void testOrganizeDoesNothingIfBelowMaxGroupSize() {
		List<GTreeNode> nodeList =
			nodes("AAA", "AAB", "AAB", "AABA", "BBA", "BBB", "BBC", "CCC", "DDD");
		List<GTreeNode> result = organize(nodeList, 10);
		assertEquals(nodeList, result);

		result = organize(nodeList, 5);
		assertNotEquals(nodeList, result);
	}

	@Test
	public void testBasicPartitioning() {
		List<GTreeNode> nodeList = nodes("AAA", "AAB", "AAC", "BBA", "BBB", "BBC", "CCC", "DDD");
		List<GTreeNode> result = organize(nodeList, 5);
		assertEquals(4, result.size());
		assertEquals("AA", result.get(0).getName());
		assertEquals("BB", result.get(1).getName());
		assertEquals("CCC", result.get(2).getName());
		assertEquals("DDD", result.get(3).getName());

		GTreeNode aaGroup = result.get(0);
		assertEquals(3, aaGroup.getChildCount());
		assertEquals("AAA", aaGroup.getChild(0).getName());
		assertEquals("AAB", aaGroup.getChild(1).getName());
		assertEquals("AAC", aaGroup.getChild(2).getName());

		GTreeNode bbGroup = result.get(1);
		assertEquals(3, bbGroup.getChildCount());
	}

	@Test
	public void testMultiLevel() {
		List<GTreeNode> nodeList = nodes("A", "B", "CAA", "CAB", "CAC", "CAD", "CAE", "CAF", "CBA");
		List<GTreeNode> result = organize(nodeList, 5);
		assertEquals(3, result.size());
		assertEquals("A", result.get(0).getName());
		assertEquals("B", result.get(1).getName());
		assertEquals("C", result.get(2).getName());

		GTreeNode cGroup = result.get(2);
		assertEquals(2, cGroup.getChildCount());
		assertEquals("CA", cGroup.getChild(0).getName());
		assertEquals("CBA", cGroup.getChild(1).getName());

		GTreeNode caGroup = cGroup.getChild(0);
		assertEquals(6, caGroup.getChildCount());
		assertEquals("CAA", caGroup.getChild(0).getName());
		assertEquals("CAF", caGroup.getChild(5).getName());
	}

	@Test
	public void testManySameLabels() {
		List<GTreeNode> nodeList =
			nodes("A", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP",
				"DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP");

		List<GTreeNode> result = organize(nodeList, 5);
		assertEquals(2, result.size());
		assertEquals("A", result.get(0).getName());
		assertEquals("DUP", result.get(1).getName());

		GTreeNode dupNode = result.get(1);
		assertEquals(OrganizationNode.MAX_SAME_NAME + 1, dupNode.getChildCount());
		assertEquals("11 more...", dupNode.getChild(OrganizationNode.MAX_SAME_NAME).getName());

	}

	@Test
	public void testRemoveNotShownNode() {
		List<GTreeNode> nodeList =
			nodes("A", "D1", "D2", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP",
				"DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP");

		List<GTreeNode> result = organize(nodeList, 5);

		SymbolTreeNode dNode = (SymbolTreeNode) result.get(1);
		GTreeNode dupNode = dNode.getChild(2);

		assertEquals(OrganizationNode.MAX_SAME_NAME + 1, dupNode.getChildCount());
		assertEquals("11 more...", dupNode.getChild(OrganizationNode.MAX_SAME_NAME).getName());

		SymbolTreeNode node = (SymbolTreeNode) nodeList.get(nodeList.size() - 1);
		simulateSmbolDeleted(dNode, node.getSymbol());

		assertEquals("10 more...", dupNode.getChild(dupNode.getChildCount() - 1).getName());
	}

	@Test
	public void testRemoveShownNode() {
		List<GTreeNode> nodeList =
			nodes("A", "D1", "D2", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP",
				"DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP");

		List<GTreeNode> result = organize(nodeList, 5);

		SymbolTreeNode dNode = (SymbolTreeNode) result.get(1);
		GTreeNode dupNode = dNode.getChild(2);

		assertEquals(OrganizationNode.MAX_SAME_NAME + 1, dupNode.getChildCount());
		assertEquals("11 more...", dupNode.getChild(OrganizationNode.MAX_SAME_NAME).getName());

		SymbolTreeNode node = (SymbolTreeNode) nodeList.get(4);
		simulateSmbolDeleted(dNode, node.getSymbol());

		assertEquals(OrganizationNode.MAX_SAME_NAME, dupNode.getChildCount());
		assertEquals("11 more...", dupNode.getChild(dupNode.getChildCount() - 1).getName());
	}

	@Test
	public void testAddDupNodeJustIncrementsCount() {
		List<GTreeNode> nodeList =
			nodes("A", "D1", "D2", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP",
				"DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP", "DUP");

		List<GTreeNode> result = organize(nodeList, 5);

		SymbolTreeNode dNode = (SymbolTreeNode) result.get(1);
		GTreeNode dupNode = dNode.getChild(2);

		assertEquals(OrganizationNode.MAX_SAME_NAME + 1, dupNode.getChildCount());
		assertEquals("11 more...", dupNode.getChild(OrganizationNode.MAX_SAME_NAME).getName());

		((OrganizationNode) dNode).insertNode(node("DUP"));

		assertEquals(OrganizationNode.MAX_SAME_NAME + 1, dupNode.getChildCount());
		assertEquals("12 more...", dupNode.getChild(OrganizationNode.MAX_SAME_NAME).getName());
	}

	@Test
	public void testEmptyNodeIsRemoved() {
		List<GTreeNode> nodeList = nodes("AA1", "AA2", "AA3", "AB1", "AB2", "AB3",
			"BB1", "BB2", "BB3", "CCC", "DDD");
		List<GTreeNode> result = organize(nodeList, 3);
		// the result should have  4 nodes, the first being the "A" node
		assertEquals(4, result.size());
		GTreeNode nodeA = result.get(0);
		assertEquals("A", nodeA.getName());

		// The A node should have 2 children AA and AB
		assertEquals(2, nodeA.getChildCount());
		GTreeNode nodeAA = nodeA.getChild(0);
		assertEquals("AA", nodeAA.getName());

		// finally the AA node should have 3 children AA1,AA2,AA3
		assertEquals(3, nodeAA.getChildCount());
		GTreeNode nodeAA1 = nodeAA.getChild(0);
		GTreeNode nodeAA2 = nodeAA.getChild(1);
		GTreeNode nodeAA3 = nodeAA.getChild(2);

		assertEquals("AA1", nodeAA1.getName());
		assertEquals("AA2", nodeAA2.getName());
		assertEquals("AA3", nodeAA3.getName());

		// remove AA1,AA2,AA3, verify that AA is removed as well
		nodeAA.removeNode(nodeAA1);
		nodeAA.removeNode(nodeAA2);
		nodeAA.removeNode(nodeAA3);

		assertEquals(1, nodeA.getChildCount());
		assertEquals("AB", nodeA.getChild(0).getName());
	}

	private void simulateSmbolDeleted(SymbolTreeNode root, Symbol symbolToDelete) {
		SymbolNode key = SymbolNode.createKeyNode(symbolToDelete, symbolToDelete.getName(), null);
		GTreeNode found = root.findSymbolTreeNode(key, false, TaskMonitor.DUMMY);
		Swing.runNow(() -> found.getParent().removeNode(found));
	}

	private List<GTreeNode> organize(List<GTreeNode> list, int size) {
		try {
			return OrganizationNode.organize(list, size, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			throw new AssertException("Can't happen");
		}
	}

	private List<GTreeNode> nodes(String... names) {
		List<GTreeNode> list = new ArrayList<>();
		for (String name : names) {
			list.add(node(name));
		}
		return list;
	}

	private GTreeNode node(String name) {
		return new CodeSymbolNode(null, new StubSymbol(name, null));
	}
}
