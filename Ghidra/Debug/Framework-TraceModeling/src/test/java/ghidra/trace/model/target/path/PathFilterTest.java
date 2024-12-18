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
package ghidra.trace.model.target.path;

import static org.junit.Assert.assertEquals;

import java.util.Set;

import org.junit.Test;

public class PathFilterTest {
	@Test
	public void testGetPrevKeys() {
		PathFilter pred = PathFilter.parse("Processes[0].Threads[].Stack");

		assertEquals(Set.of("Stack"), pred.getPrevKeys(KeyPath.ROOT));
		assertEquals(Set.of("[]"), pred.getPrevKeys(KeyPath.parse("Stack")));
		assertEquals(Set.of("Threads"), pred.getPrevKeys(KeyPath.parse("[].Stack")));
		assertEquals(Set.of("[0]"), pred.getPrevKeys(KeyPath.parse("Threads[].Stack")));
		assertEquals(Set.of("Processes"), pred.getPrevKeys(KeyPath.parse("[0].Threads[].Stack")));
		assertEquals(Set.of(), pred.getPrevKeys(KeyPath.parse("Processes[0].Threads[].Stack")));

		assertEquals(Set.of(), pred.getPrevKeys(KeyPath.parse("Foo.Processes[0].Threads[].Stack")));
		assertEquals(Set.of(), pred.getPrevKeys(KeyPath.parse("Foo")));
		assertEquals(Set.of(), pred.getPrevKeys(KeyPath.parse("[]")));
	}
}
