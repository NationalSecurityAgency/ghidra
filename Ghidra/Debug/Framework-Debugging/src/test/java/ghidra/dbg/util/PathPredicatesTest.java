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
package ghidra.dbg.util;

import static org.junit.Assert.assertEquals;

import java.util.Set;

import org.junit.Test;

public class PathPredicatesTest {
	@Test
	public void testGetPrevKeys() {
		PathPredicates pred = PathPredicates.parse("Processes[0].Threads[].Stack");

		assertEquals(Set.of("Stack"), pred.getPrevKeys(PathUtils.parse("")));
		assertEquals(Set.of("[]"), pred.getPrevKeys(PathUtils.parse("Stack")));
		assertEquals(Set.of("Threads"), pred.getPrevKeys(PathUtils.parse("[].Stack")));
		assertEquals(Set.of("[0]"), pred.getPrevKeys(PathUtils.parse("Threads[].Stack")));
		assertEquals(Set.of("Processes"), pred.getPrevKeys(PathUtils.parse("[0].Threads[].Stack")));
		assertEquals(Set.of(), pred.getPrevKeys(PathUtils.parse("Processes[0].Threads[].Stack")));

		assertEquals(Set.of(),
			pred.getPrevKeys(PathUtils.parse("Foo.Processes[0].Threads[].Stack")));
		assertEquals(Set.of(), pred.getPrevKeys(PathUtils.parse("Foo")));
		assertEquals(Set.of(), pred.getPrevKeys(PathUtils.parse("[]")));
	}
}
