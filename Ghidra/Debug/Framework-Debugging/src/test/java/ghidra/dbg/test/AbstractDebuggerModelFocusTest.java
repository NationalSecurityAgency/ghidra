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
package ghidra.dbg.test;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeNotNull;

import java.util.List;
import java.util.Set;

import org.junit.Test;

import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;

public abstract class AbstractDebuggerModelFocusTest extends AbstractDebuggerModelTest {

	/**
	 * Get (possibly generate) things for this focus test to try out
	 * 
	 * @throws Throwable if anything goes wrong
	 */
	protected abstract Set<TargetObject> getFocusableThings() throws Throwable;

	/**
	 * Governs whether assertions permit the actual object to be a successor of the expected object
	 * 
	 * @return true to permit successors, false to require exact
	 */
	protected boolean permitSuccessor() {
		return true;
	}

	protected void assertSuccessorOrExact(TargetObject expected, TargetObject actual) {
		assertNotNull(actual);
		if (permitSuccessor()) {
			assertTrue("Expected successor of '" + expected.getJoinedPath(".") +
				"' got '" + actual.getJoinedPath(".") + "'",
				PathUtils.isAncestor(expected.getPath(), actual.getPath()));
		}
		else {
			assertSame(expected, actual);
		}
	}

	/**
	 * If the default focus is one of the focusable things (after generation), assert its path
	 * 
	 * @return the path of the expected default focus, or {@code null} for no assertion
	 */
	protected List<String> getExpectedDefaultFocus() {
		return null;
	}

	@Test
	public void testDefaultFocusIsAsExpected() throws Throwable {
		List<String> expectedDefaultFocus = getExpectedDefaultFocus();
		assumeNotNull(expectedDefaultFocus);
		m.build();

		TargetFocusScope scope = findFocusScope();
		Set<TargetObject> focusable = getFocusableThings();
		// The default must be one of the focusable objects
		assertTrue(focusable.stream()
				.anyMatch(f -> PathUtils.isAncestor(f.getPath(), expectedDefaultFocus)));
		retryVoid(() -> {
			assertEquals(expectedDefaultFocus, scope.getFocus().getPath());
		}, List.of(AssertionError.class));
	}

	@Test
	public void testFocusEachOnce() throws Throwable {
		m.build();

		TargetFocusScope scope = findFocusScope();
		Set<TargetObject> focusable = getFocusableThings();
		for (TargetObject obj : focusable) {
			waitOn(scope.requestFocus(obj));
			retryVoid(() -> {
				assertSuccessorOrExact(obj, scope.getFocus());
			}, List.of(AssertionError.class));
		}
	}

	@Test
	public void testFocusEachTwice() throws Throwable {
		m.build();

		TargetFocusScope scope = findFocusScope();
		Set<TargetObject> focusable = getFocusableThings();
		for (TargetObject obj : focusable) {
			waitOn(scope.requestFocus(obj));
			retryVoid(() -> {
				assertSuccessorOrExact(obj, scope.getFocus());
			}, List.of(AssertionError.class));
			waitOn(scope.requestFocus(obj));
			retryVoid(() -> {
				assertSuccessorOrExact(obj, scope.getFocus());
			}, List.of(AssertionError.class));
		}
	}
}
