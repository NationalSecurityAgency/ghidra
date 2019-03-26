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
package ghidra.app.util.bin.format.dwarf4;

import org.junit.Assert;
import org.junit.Test;

import ghidra.app.util.bin.format.dwarf4.next.NamespacePath;
import ghidra.program.model.symbol.SymbolType;

public class NamespacePathTest {

	@Test
	public void test() {
		NamespacePath nsp = NamespacePath.create(null, "sub1", SymbolType.NAMESPACE);
		NamespacePath nsp1_1 = NamespacePath.create(nsp, "sub1_1", SymbolType.NAMESPACE);

		Assert.assertEquals("ROOT::sub1", nsp.asNamespaceString());
		Assert.assertEquals("ROOT::sub1::sub1_1", nsp1_1.asNamespaceString());
		Assert.assertEquals("/sub1", nsp.asCategoryPathString());
		Assert.assertEquals("/sub1/sub1_1", nsp1_1.asCategoryPathString());

	}

	@Test
	public void testMangle() {
		NamespacePath nsSlashA = NamespacePath.create(null, "ns/A", SymbolType.NAMESPACE);
		NamespacePath nsSpaceA = NamespacePath.create(null, "ns A", SymbolType.NAMESPACE);
		NamespacePath nsColonA = NamespacePath.create(null, "ns:A", SymbolType.NAMESPACE);

		Assert.assertEquals("ROOT::ns-fwdslash-A", nsSlashA.asNamespaceString());
		Assert.assertEquals("ROOT::nsA", nsSpaceA.asNamespaceString());
		Assert.assertEquals("ROOT::ns-A", nsColonA.asNamespaceString());
	}
}
