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

import java.util.List;

import org.junit.Test;

public class GoSymbolNameTest {
	@Test
	public void testParse() {
		GoSymbolName gsn = GoSymbolName.parse("internal/fmtsort.(*SortedMap).Len");
		assertEquals("internal/fmtsort", gsn.getPackagePath());
		assertEquals("fmtsort", gsn.getPackageName());
		assertEquals("*SortedMap", gsn.getReceiverString());

		gsn = GoSymbolName.parse("runtime..inittask");
		assertEquals("runtime", gsn.getPackagePath());
		assertEquals("runtime", gsn.getPackageName());
		assertEquals(".inittask", gsn.getBaseName());
		assertNull(gsn.getReceiverString());
		assertEquals("runtime..inittask", gsn.asString());

		gsn = GoSymbolName.parse("crypto/ecdsa.inverse[go.shape.*uint8]");
		assertEquals("crypto/ecdsa", gsn.getPackagePath());
		assertEquals("ecdsa", gsn.getPackageName());
		assertNull(gsn.getReceiverString());

		gsn = GoSymbolName.parse("time.parseRFC3339[go.shape.[]uint8]");
		assertEquals("time", gsn.getPackagePath());
		assertEquals("time", gsn.getPackageName());
		assertNull(gsn.getReceiverString());
		assertEquals("go.shape.[]uint8", gsn.getGenericsString());
		assertEquals("parseRFC3339", gsn.baseName());
		assertEquals("time.parseRFC3339", gsn.getStrippedSymbolString());

		gsn = GoSymbolName.parse("sync/atomic.(*Pointer[interface_{}]).Load");
		assertEquals("sync/atomic", gsn.getPackagePath());
		assertEquals("atomic", gsn.getPackageName());
		assertEquals("*Pointer[interface_{}]", gsn.getReceiverString());
		assertEquals("sync/atomic.(*Pointer).Load", gsn.getStrippedSymbolString());
		assertEquals("interface_{}", gsn.getGenericsString());
		assertEquals(List.of("interface_{}"), gsn.getGenericParts());
		assertEquals(1, gsn.getGenericParts().size());

		gsn = GoSymbolName.parse(
			"slices.stableCmpFunc[go.shape.struct { Key reflect.Value; Value reflect.Value }]");
		assertEquals("slices", gsn.getPackagePath());
		assertEquals("slices", gsn.getPackageName());
		assertEquals("stableCmpFunc", gsn.getBaseName());
		assertNull(gsn.getReceiverString());
		assertEquals("go.shape.struct { Key reflect.Value; Value reflect.Value }",
			gsn.getGenericsString());
		assertEquals(1, gsn.getGenericParts().size());

		gsn = GoSymbolName.parse(
			"main.(*genericstruct[go.shape.string,go.shape.int,go.shape.string]).bar_takes_genericstruct");
		assertEquals("main", gsn.getPackagePath());
		assertEquals("main", gsn.getPackageName());
		assertEquals("*genericstruct[go.shape.string,go.shape.int,go.shape.string]",
			gsn.getReceiverString());
		assertEquals("go.shape.string,go.shape.int,go.shape.string", gsn.getGenericsString());
		assertEquals(List.of("go.shape.string", "go.shape.int", "go.shape.string"),
			gsn.getGenericParts());
		assertEquals(3, gsn.getGenericParts().size());

		GoSymbolName gensym1 =
			GoSymbolName.parseTypeName(gsn.getGenericParts().get(0), gsn.getPackageName());
		assertEquals("go.shape", gensym1.getPackageName());
		assertEquals("go.shape", gensym1.getPackagePath());
		assertEquals("string", gensym1.getBaseName());

		gsn = GoSymbolName.parse(
			"main.(*genericstruct[go.shape.interface_{_F();_FF(bool);_FFF(bool,_int)_},go.shape.int,go.shape.string]).bar_takes_genericstruct");
		assertEquals("main", gsn.getPackagePath());
		assertEquals("main", gsn.getPackageName());
		assertEquals(
			"*genericstruct[go.shape.interface_{_F();_FF(bool);_FFF(bool,_int)_},go.shape.int,go.shape.string]",
			gsn.getReceiverString());
		assertEquals(
			"go.shape.interface_{_F();_FF(bool);_FFF(bool,_int)_},go.shape.int,go.shape.string",
			gsn.getGenericsString());
		assertEquals(List.of("go.shape.interface_{_F();_FF(bool);_FFF(bool,_int)_}", "go.shape.int",
			"go.shape.string"), gsn.getGenericParts());
		assertEquals(3, gsn.getGenericParts().size());
		assertEquals("main.(*genericstruct).bar_takes_genericstruct",
			gsn.getStrippedSymbolString());

		GoSymbolName rtn = gsn.getReceiverTypeName();
		assertEquals("main", rtn.getPackagePath());
		assertEquals("main", rtn.getPackageName());
		assertEquals(
			"*main.genericstruct[go.shape.interface_{_F();_FF(bool);_FFF(bool,_int)_},go.shape.int,go.shape.string]",
			rtn.asString());

	}

	@Test
	public void testPackagePathWithDots() {
		// test dots in the packagepath string
		GoSymbolName gsn =
			GoSymbolName.parse("vendor/golang.org/x/text/unicode/norm.(*reorderBuffer).compose");
		assertEquals("vendor/golang.org/x/text/unicode/norm", gsn.getPackagePath());
		assertEquals("norm", gsn.getPackageName());
		assertEquals("*reorderBuffer", gsn.getReceiverString());
		assertEquals("compose", gsn.getBaseName());
	}

	@Test
	public void testTypenameWithLongPP() {
		GoSymbolName gsn = GoSymbolName.parse(
			"type:.eq.github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/internal/base.Client[go.shape.struct { github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/internal/generated.internal *github.com/Azure/azure-sdk-for-go/sdk/azcore.Client; github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/internal/generated.endpoint string }]");
		assertEquals("github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/internal/base",
			gsn.getPackagePath());
	}

	@Test
	public void testSlashesInRecvGenericsStr() {
		// test slashes/dots in the receiver string
		GoSymbolName gsn = GoSymbolName.parse("sync/atomic.(*Pointer[net/http.response]).Store");
		assertEquals("sync/atomic", gsn.getPackagePath());
		assertEquals("atomic", gsn.getPackageName());
		assertEquals("*Pointer[net/http.response]", gsn.getReceiverString());
		assertEquals("Store", gsn.getBaseName());
	}

	@Test
	public void testGoPrefix() {
		GoSymbolName gsn =
			GoSymbolName.parse("go:(*struct_{_runtime.gList;_runtime.n_int32_}).runtime.empty");
		assertNull(gsn.getPackagePath());
		assertNull(gsn.getPackageName());
		assertNull(gsn.getReceiverString());
		assertEquals("go:(*struct_{_runtime.gList;_runtime.n_int32_}).runtime.empty",
			gsn.getStrippedSymbolString());
	}

	@Test
	public void testAnonFunc() {
		GoSymbolName gsn = GoSymbolName.parse("runtime.addOneOpenDeferFrame.func1");
		assertEquals("runtime", gsn.getPackagePath());
		assertEquals("runtime", gsn.getPackageName());
		assertEquals("addOneOpenDeferFrame.func1", gsn.getBaseName());
		assertEquals(GoSymbolNameType.ANON_FUNC, gsn.getNameType());
		assertNull(gsn.getReceiverString());
	}

	@Test
	public void testSimpleGeneric() {
		GoSymbolName gsn = GoSymbolName.parse("internal/poll.somefunc[go.shape.bool]");
		assertEquals("internal/poll", gsn.getPackagePath());
		assertEquals("poll", gsn.getPackageName());
		assertEquals("somefunc", gsn.getBaseName());
		assertNull(gsn.getReceiverString());
		assertEquals("go.shape.bool", gsn.getGenericsString());
		assertEquals(GoSymbolNameType.FUNC, gsn.getNameType());

		gsn = GoSymbolName.parse("internal/poll.somefunc[go.shape.bool].func5");
		assertEquals("internal/poll", gsn.getPackagePath());
		assertEquals("poll", gsn.getPackageName());
		assertEquals("somefunc[go.shape.bool].func5", gsn.getBaseName());
		assertNull(gsn.getGenericsString());
		assertNull(gsn.getReceiverString());
		assertEquals(GoSymbolNameType.ANON_FUNC, gsn.getNameType());

	}

	@Test
	public void testRecvGeneric() {
		GoSymbolName sni = GoSymbolName.parse("sync/atomic.(*Pointer[os.dirInfo]).CompareAndSwap");
		assertEquals("sync/atomic", sni.getPackagePath());
		assertEquals("atomic", sni.getPackageName());
		assertEquals("*Pointer[os.dirInfo]", sni.getReceiverString());
		assertEquals("*Pointer", sni.getStrippedReceiverString());
		assertEquals("os.dirInfo", sni.getGenericsString());
		assertEquals(List.of("os.dirInfo"), sni.getGenericParts());
		assertEquals(1, sni.getGenericParts().size());
		assertEquals("sync/atomic.(*Pointer).CompareAndSwap", sni.getStrippedSymbolString());

		GoSymbolName gsn = sni.getReceiverTypeName();
		assertEquals("sync/atomic", gsn.getPackagePath());
		assertEquals("atomic", gsn.getPackageName());
		assertEquals("Pointer[os.dirInfo]", gsn.getBaseName());
		assertEquals("*", gsn.getPrefix());
		assertEquals("*sync/atomic.Pointer[os.dirInfo]", gsn.asString());
	}

	@Test
	public void testNestedRecvStrings() {
		GoSymbolName sni =
			GoSymbolName.parse("runtime.(*sweepLocked).sweep.(*mheap).freeSpan.func4");
		assertEquals("runtime", sni.getPackagePath());
		assertEquals("runtime", sni.getPackageName());
		assertEquals("sweep.(*mheap).freeSpan.func4", sni.getBaseName());
		assertEquals("*sweepLocked", sni.getReceiverString());
		assertEquals(GoSymbolNameType.ANON_FUNC, sni.getNameType());

		sni = GoSymbolName.parse(
			"runtime.(*sweepLocked[genericinfo{ func() }]).sweep.(*mheap).freeSpan.func4");
		assertEquals("runtime", sni.getPackagePath());
		assertEquals("runtime", sni.getPackageName());
		assertEquals("sweep.(*mheap).freeSpan.func4", sni.getBaseName());
		assertEquals("*sweepLocked[genericinfo{ func() }]", sni.getReceiverString());
		assertEquals("*sweepLocked", sni.getStrippedReceiverString());
		assertEquals(GoSymbolNameType.ANON_FUNC, sni.getNameType());
	}

	@Test
	public void testTypeNames() {
		GoSymbolName sni = GoSymbolName.parseTypeName("int", "");
		assertEquals("", sni.getPackageName());
		assertEquals("", sni.getPackagePath());
		assertEquals("int", sni.getBaseName());
		assertEquals("int", sni.asString());
		assertEquals("", sni.getPrefix());

		sni = GoSymbolName.parseTypeName("plaintypename", "package1");
		assertEquals("package1", sni.getPackageName());
		assertEquals("package1", sni.getPackagePath());
		assertEquals("plaintypename", sni.getBaseName());
		assertEquals("package1.plaintypename", sni.asString());
		assertEquals("", sni.getPrefix());

		sni = GoSymbolName.parseTypeName("*[][3][..]plaintypename", "package1");
		assertEquals("package1", sni.getPackageName());
		assertEquals("package1", sni.getPackagePath());
		assertEquals("plaintypename", sni.getBaseName());
		assertEquals("*[][3][..]package1.plaintypename", sni.asString());
		assertEquals("*[][3][..]", sni.getPrefix());

		sni = GoSymbolName.parseTypeName("*atomic.Pointer[interface {}]", "sync/atomic");
		assertEquals("atomic", sni.getPackageName());
		assertEquals("sync/atomic", sni.getPackagePath());
		assertEquals("Pointer[interface {}]", sni.getBaseName());
		assertEquals("*sync/atomic.Pointer[interface {}]", sni.asString());
		assertEquals("*", sni.getPrefix());

		// mismatch package name
		sni = GoSymbolName.parseTypeName("*atomic.Pointer[interface {}]", "sync/atomicx");
		assertEquals("atomic", sni.getPackageName());
		assertEquals("atomic", sni.getPackagePath());
		assertEquals("Pointer[interface {}]", sni.getBaseName());
		assertEquals("*atomic.Pointer[interface {}]", sni.asString());
		assertEquals("*", sni.getPrefix());

		sni = GoSymbolName.parseTypeName("struct { runtime.gList; runtime.n int32 }", null);
		assertEquals("", sni.getPackageName());
		assertEquals("", sni.getPackagePath());
		assertEquals("struct { runtime.gList; runtime.n int32 }", sni.getBaseName());
		assertEquals("struct { runtime.gList; runtime.n int32 }", sni.asString());
		assertEquals("", sni.getPrefix());

		sni = GoSymbolName.parseTypeName("go.shape.interface { Foo() type }", null);
		assertEquals("go.shape", sni.getPackageName());
		assertEquals("go.shape", sni.getPackagePath());
		assertEquals("interface { Foo() type }", sni.getBaseName());
		assertEquals("go.shape.interface { Foo() type }", sni.asString());
		assertEquals("", sni.getPrefix());

		sni = GoSymbolName.parseTypeName("*[]runtime.ancestorInfo", null);
		assertEquals("runtime", sni.getPackageName());
		assertEquals("runtime", sni.getPackagePath());
		assertEquals("ancestorInfo", sni.getBaseName());
		assertEquals("*[]runtime.ancestorInfo", sni.asString());
		assertEquals("*[]", sni.getPrefix());

		sni = GoSymbolName.parseTypeName("*metadata.mdValue",
			"google.golang.org/grpc/internal/metadata");
		assertEquals("metadata", sni.getPackageName());
		assertEquals("google.golang.org/grpc/internal/metadata", sni.getPackagePath());
		assertEquals("mdValue", sni.getBaseName());
		assertEquals("*google.golang.org/grpc/internal/metadata.mdValue", sni.asString());
		assertEquals("*", sni.getPrefix());

		sni = GoSymbolName.parseTypeName("*func(blah) blah", "package1");
		assertEquals("package1", sni.getPackageName());
		assertEquals("package1", sni.getPackagePath());
		assertEquals("func(blah) blah", sni.getBaseName());
		assertEquals("*package1.func(blah) blah", sni.asString());
		assertEquals("*", sni.getPrefix());

		sni = GoSymbolName.parseTypeName("gopkg.in/struct { }", "");
		assertEquals("", sni.getPackageName());
		assertEquals("gopkg.in/", sni.getPackagePath());
		assertEquals("struct { }", sni.getBaseName());
		assertEquals("gopkg.in/struct { }", sni.asString());
		assertEquals("", sni.getPrefix());

		sni = GoSymbolName.parseTypeName(
			"*struct { ProjectID string \"json:\\\"project_id\\\"\"; Project string \"json:\\\"project\\\"\" }",
			"");
		assertEquals("", sni.getPackageName());
		assertEquals("", sni.getPackagePath());
		assertEquals(
			"struct { ProjectID string \"json:\\\"project_id\\\"\"; Project string \"json:\\\"project\\\"\" }",
			sni.getBaseName());
		assertEquals(
			"*struct { ProjectID string \"json:\\\"project_id\\\"\"; Project string \"json:\\\"project\\\"\" }",
			sni.asString());
		assertEquals("*", sni.getPrefix());
	}

	@Test
	public void testTypeNamePackage() {
		GoSymbolName sni = GoSymbolName.parseTypeName(
			"github.com/restic/restic/internal/debug.eofDetectRoundTripper", null);
		assertEquals("debug", sni.getPackageName());
		assertEquals("github.com/restic/restic/internal/debug", sni.getPackagePath());
		assertEquals("eofDetectRoundTripper", sni.getBaseName());
		assertEquals("github.com/restic/restic/internal/debug.eofDetectRoundTripper",
			sni.asString());
		assertEquals("", sni.getPrefix());
	}

	@Test
	public void testNonPtrReceiver() {
		GoSymbolName sni = GoSymbolName.parse("runtime.sometype.SomeMethod");
		assertEquals("runtime", sni.getPackagePath());
		assertEquals("runtime", sni.getPackageName());
		assertEquals("sometype.SomeMethod", sni.getBaseName());
		assertNull(sni.getReceiverString());
		assertEquals(GoSymbolNameType.UNKNOWN, sni.getNameType());
		assertTrue(sni.isNonPtrReceiverCandidate());

		sni = sni.asNonPtrReceiverSymbolName();
		assertEquals("runtime", sni.getPackagePath());
		assertEquals("runtime", sni.getPackageName());
		assertEquals("SomeMethod", sni.getBaseName());
		assertEquals("sometype", sni.getReceiverString());
	}

	@Test
	public void testParseTypeSymbol() {
		GoSymbolName sni = GoSymbolName.parse("type:.eq.runtime/internal/atomic.Int64");
		assertEquals("runtime/internal/atomic", sni.getPackagePath());
		assertEquals("atomic", sni.getPackageName());
		assertNull(sni.getReceiverString());
		assertEquals("type:.eq.", sni.getPrefix());

		sni = GoSymbolName.parse("type:.eq.struct_{_runtime.gList;_runtime.n_int32_}");
		assertEquals("", sni.getPackagePath());
		assertEquals("", sni.getPackageName());
		assertNull(sni.getReceiverString());
		assertEquals("type:.eq.", sni.getPrefix());

		sni = GoSymbolName.parse("type:.eq.sync/atomic.Pointer[interface_{}]");
		assertEquals("sync/atomic", sni.getPackagePath());
		assertEquals("atomic", sni.getPackageName());
		assertNull(sni.getReceiverString());
		assertEquals("type:.eq.", sni.getPrefix());

		sni = GoSymbolName.parse("type:.eq.[...]internal/cpu.option");
		assertEquals("internal/cpu", sni.getPackagePath());
		assertEquals("cpu", sni.getPackageName());
		assertEquals("[...]internal/cpu.option", sni.getBaseName());
		assertNull(sni.getReceiverString());
		assertEquals("type:.eq.", sni.getPrefix());

		sni = GoSymbolName.parse("type:.eq.[39]vendor/golang.org/x/sys/cpu.option");
		assertEquals("vendor/golang.org/x/sys/cpu", sni.getPackagePath());
		assertEquals("cpu", sni.getPackageName());
		assertEquals("[39]vendor/golang.org/x/sys/cpu.option", sni.getBaseName());
		assertNull(sni.getReceiverString());
		assertEquals("type:.eq.", sni.getPrefix());
	}

}
