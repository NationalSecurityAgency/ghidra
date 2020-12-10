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
package experiments;

import java.util.*;
import java.util.function.IntConsumer;

import org.junit.Ignore;
import org.junit.Test;

public class ToArrayTest {

	long time(int n, IntConsumer run) {
		long start = System.currentTimeMillis();
		run.accept(n);
		return System.currentTimeMillis() - start;
	}

	protected void runTest(Collection<String> col) {
		for (int i = 0; i < 10000000; i += 1000000) {
			System.out.println("  Loops: " + i);

			System.out.print("    toArray(String[]::new): ");
			System.out.println(time(i, n -> {
				for (int j = 0; j < n; j++) {
					col.toArray(String[]::new);
				}
			}) + "ms");

			System.out.print("    toArray(new String[0]): ");
			System.out.println(time(i, n -> {
				for (int j = 0; j < n; j++) {
					col.toArray(new String[0]);
				}
			}) + "ms");

			System.out.print("    toArray(new String[n]): ");
			System.out.println(time(i, n -> {
				for (int j = 0; j < n; j++) {
					col.toArray(new String[col.size()]);
				}
			}) + "ms");
		}
	}

	protected void fillCollection(Collection<String> col, int n) {
		for (int i = 0; i < n; i++) {
			col.add("String" + i);
		}
	}

	@Test
	@Ignore
	public void testHashSetToArrayPerformance() {
		System.out.println("HashSet<String>(10):");
		Collection<String> col = new HashSet<>();
		fillCollection(col, 10);
		runTest(col);
	}

	@Test
	@Ignore
	public void testArrayListToArrayPerformance() {
		System.out.println("ArrayList<String>(10):");
		Collection<String> col = new ArrayList<>();
		fillCollection(col, 10);
		runTest(col);
	}
}
