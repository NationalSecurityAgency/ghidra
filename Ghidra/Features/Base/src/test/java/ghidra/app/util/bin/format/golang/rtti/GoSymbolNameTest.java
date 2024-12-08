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
package ghidra.app.util.bin.format.golang.rtti;

import static org.junit.Assert.*;

import org.junit.Test;

public class GoSymbolNameTest {
	@Test
	public void testParse() {
		GoSymbolName sni = GoSymbolName.parse("internal/fmtsort.(*SortedMap).Len");
		assertEquals("internal/fmtsort", sni.getPackagePath());
		assertEquals("fmtsort", sni.getPackageName());
		assertEquals("*SortedMap", sni.getRecieverString());

		sni = GoSymbolName.parse("runtime..inittask");
		assertEquals("runtime", sni.getPackagePath());
		assertEquals("runtime", sni.getPackageName());
		assertNull(sni.getRecieverString());

		sni = GoSymbolName.parse("runtime.addOneOpenDeferFrame.func1");
		assertEquals("runtime", sni.getPackagePath());
		assertEquals("runtime", sni.getPackageName());
		assertNull(sni.getRecieverString());

		// test dots in the packagepath string
		sni = GoSymbolName
				.parse("vendor/golang.org/x/text/unicode/norm.(*reorderBuffer).compose");
		assertEquals("vendor/golang.org/x/text/unicode/norm", sni.getPackagePath());
		assertEquals("norm", sni.getPackageName());
		assertEquals("*reorderBuffer", sni.getRecieverString());

		// test slashes/dots in the receiver string
		sni = GoSymbolName.parse("sync/atomic.(*Pointer[net/http.response]).Store");
		assertEquals("sync/atomic", sni.getPackagePath());
		assertEquals("atomic", sni.getPackageName());
		assertEquals("*Pointer[net/http.response]", sni.getRecieverString());

		sni = GoSymbolName.parse("crypto/ecdsa.inverse[go.shape.*uint8]");
		assertEquals("crypto/ecdsa", sni.getPackagePath());
		assertEquals("ecdsa", sni.getPackageName());
		assertNull(sni.getRecieverString());

		sni =
			GoSymbolName.parse("go:(*struct_{_runtime.gList;_runtime.n_int32_}).runtime.empty");
		assertNull(sni.getPackagePath());
		assertNull(sni.getPackageName());
		assertNull(sni.getRecieverString());

		sni = GoSymbolName.parse("time.parseRFC3339[go.shape.[]uint8]");
		assertEquals("time", sni.getPackagePath());
		assertEquals("time", sni.getPackageName());
		assertNull(sni.getRecieverString());

		sni = GoSymbolName.parse("sync/atomic.(*Pointer[interface_{}]).Load");
		assertEquals("sync/atomic", sni.getPackagePath());
		assertEquals("atomic", sni.getPackageName());
		assertEquals("*Pointer[interface_{}]", sni.getRecieverString());
	}

	@Test
	public void testParseTypeSymbol() {
		GoSymbolName sni = GoSymbolName.parse("type:.eq.runtime/internal/atomic.Int64");
		assertEquals("runtime/internal/atomic", sni.getPackagePath());
		assertEquals("atomic", sni.getPackageName());
		assertNull(sni.getRecieverString());

		sni = GoSymbolName.parse("type:.eq.struct_{_runtime.gList;_runtime.n_int32_}");
		assertNull(sni.getPackagePath());
		assertNull(sni.getPackageName());
		assertNull(sni.getRecieverString());

		sni = GoSymbolName.parse("type:.eq.sync/atomic.Pointer[interface_{}]");
		assertEquals("sync/atomic", sni.getPackagePath());
		assertEquals("atomic", sni.getPackageName());
		assertNull(sni.getRecieverString());

		sni = GoSymbolName.parse("type:.eq.[...]internal/cpu.option");
		assertEquals("internal/cpu", sni.getPackagePath());
		assertEquals("cpu", sni.getPackageName());
		assertNull(sni.getRecieverString());

		sni = GoSymbolName.parse("type:.eq.[39]vendor/golang.org/x/sys/cpu.option");
		assertEquals("vendor/golang.org/x/sys/cpu", sni.getPackagePath());
		assertEquals("cpu", sni.getPackageName());
		assertNull(sni.getRecieverString());

	}
}
