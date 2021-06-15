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
package ghidra.app.plugin.core.diff;

import static org.junit.Assert.*;

import java.util.List;

import javax.swing.JDialog;

import org.junit.Test;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.Equate;

/**
 * Tests the Ignore function of the Diff Tool, such that the current difference is ignored and
 * the next difference is selected
 */
public class DiffIgnoreTest extends DiffApplyTestAdapter {

	/*
	 * Tests that a difference is ignored and the next difference is selected
	 */
	@Test
	public void testIgnoreDiffsNextActionFirst() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForPostedSwingRunnables();

		byte[] bytes = diffTestP1.getListing().getCodeUnitAt(addr("100")).getBytes();
		assertEquals((byte) 0xac, bytes[0]);

		AddressSet addrSet = new AddressSet(addr("100"), addr("1ff"));
		setDiffSelection(addrSet);
		setLocation("100");
		ignoreAndNext();

		checkDiffSelection(new AddressSet(addr("00000200"), addr("000002ff")));
		assertTrue(diffPlugin.getDiffHighlightSelection().intersect(addrSet).isEmpty());
		assertEquals(addr("00000200"), getDiffAddress());
		bytes = diffTestP1.getListing().getCodeUnitAt(addr("100")).getBytes();
		assertEquals((byte) 0xac, bytes[0]);
	}

	/*
	 * Test that Equate Tables are properly ignored and the next difference is properly selected
	 */
	@Test
	public void testIgnoreDiffsNextActionMiddle() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForPostedSwingRunnables();

		List<Equate> eqs = diffTestP1.getEquateTable().getEquates(addr("1002261"), 0);
		assertEquals(0, eqs.size());

		AddressSet addrSet = new AddressSet(addr("1002261"), addr("1002262"));
		setDiffSelection(addrSet);
		setLocation("1002261"); // has Equate Diff
		ignoreAndNext();

		checkDiffSelection(new AddressSet(addr("10022d4"), addr("10022e5")));
		assertEquals(addr("10022d4"), getDiffAddress());
		eqs = program.getEquateTable().getEquates(addr("1002261"), 0);
		assertEquals(0, eqs.size());
	}

	/*
	 * Tests that the ignore button is disabled after ignoring the last difference
	 */
	@Test
	public void testIgnoreDiffsNextActionLast() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForPostedSwingRunnables();

		AddressSet addrSet = new AddressSet(addr("1005e4f"), addr("1005e53"));
		setDiffSelection(addrSet);
		setLocation("1005e4f");
		ignoreAndNext();
		assertTrue(!ignoreDiffs.isEnabled());
	}
}
