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
package ghidra.dbg.target;

import static org.junit.Assert.*;

import java.lang.invoke.MethodHandles;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.junit.Test;

import ghidra.async.AsyncTestUtils;
import ghidra.async.AsyncUtils;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.model.*;
import ghidra.dbg.target.TargetMethod.*;

public class TargetMethodTest implements AsyncTestUtils {
	@Test
	public void testAnnotatedMethodVoid0Args() throws Throwable {
		TestDebuggerModelBuilder mb = new TestDebuggerModelBuilder() {
			@Override
			protected TestDebuggerObjectModel newModel(String typeHint) {
				return new TestDebuggerObjectModel(typeHint) {
					@Override
					protected TestTargetThread newTestTargetThread(
							TestTargetThreadContainer container, int tid) {
						return new TestTargetThread(container, tid) {
							{
								changeAttributes(List.of(),
									AnnotatedTargetMethod.collectExports(MethodHandles.lookup(),
										testModel, this),
									"Methods");
							}

							@TargetMethod.Export("MyMethod")
							public CompletableFuture<Void> myMethod() {
								return AsyncUtils.nil();
							}
						};
					}
				};
			}
		};
		mb.createTestModel();
		mb.createTestProcessesAndThreads();
		TargetMethod method = (TargetMethod) mb.testThread1.getCachedAttribute("MyMethod");
		assertEquals(Void.class, method.getReturnType());
		assertEquals(TargetParameterMap.of(), method.getParameters());
		assertNull(waitOn(method.invoke(Map.of())));

		try {
			waitOn(method.invoke(Map.ofEntries(Map.entry("p1", "err"))));
			fail("Didn't catch extraneous argument");
		}
		catch (DebuggerIllegalArgumentException e) {
			// pass
		}
	}

	@Test
	public void testAnnotatedMethodVoid1ArgBool() throws Throwable {
		TestDebuggerModelBuilder mb = new TestDebuggerModelBuilder() {
			@Override
			protected TestDebuggerObjectModel newModel(String typeHint) {
				return new TestDebuggerObjectModel(typeHint) {
					@Override
					protected TestTargetThread newTestTargetThread(
							TestTargetThreadContainer container, int tid) {
						return new TestTargetThread(container, tid) {
							{
								changeAttributes(List.of(),
									AnnotatedTargetMethod.collectExports(MethodHandles.lookup(),
										testModel, this),
									"Methods");
							}

							@TargetMethod.Export("MyMethod")
							public CompletableFuture<Void> myMethod(
									@TargetMethod.Param(
										display = "P1",
										description = "A boolean param",
										name = "p1") boolean b) {
								return AsyncUtils.nil();
							}
						};
					}
				};
			}
		};
		mb.createTestModel();
		mb.createTestProcessesAndThreads();
		TargetMethod method = (TargetMethod) mb.testThread1.getCachedAttribute("MyMethod");
		assertEquals(Void.class, method.getReturnType());
		assertEquals(TargetParameterMap.ofEntries(
			Map.entry("p1",
				ParameterDescription.create(Boolean.class, "p1", true, null, "P1",
					"A boolean param"))),
			method.getParameters());
		assertNull(waitOn(method.invoke(Map.ofEntries(Map.entry("p1", true)))));

		try {
			waitOn(method.invoke(Map.ofEntries(Map.entry("p1", "err"))));
			fail("Didn't catch type mismatch");
		}
		catch (DebuggerIllegalArgumentException e) {
			// pass
		}

		try {
			waitOn(method.invoke(Map.ofEntries(
				Map.entry("p1", true),
				Map.entry("p2", "err"))));
			fail("Didn't catch extraneous argument");
		}
		catch (DebuggerIllegalArgumentException e) {
			// pass
		}

		try {
			waitOn(method.invoke(Map.ofEntries()));
			fail("Didn't catch missing argument");
		}
		catch (DebuggerIllegalArgumentException e) {
			// pass
		}
	}

	@Test
	public void testAnnotatedMethodString1ArgInt() throws Throwable {
		TestDebuggerModelBuilder mb = new TestDebuggerModelBuilder() {
			@Override
			protected TestDebuggerObjectModel newModel(String typeHint) {
				return new TestDebuggerObjectModel(typeHint) {
					@Override
					protected TestTargetThread newTestTargetThread(
							TestTargetThreadContainer container, int tid) {
						return new TestTargetThread(container, tid) {
							{
								changeAttributes(List.of(),
									AnnotatedTargetMethod.collectExports(MethodHandles.lookup(),
										testModel, this),
									"Methods");
							}

							@TargetMethod.Export("MyMethod")
							public CompletableFuture<String> myMethod(
									@TargetMethod.Param(
										display = "P1",
										description = "An int param",
										name = "p1") int i) {
								return CompletableFuture.completedFuture(Integer.toString(i));
							}
						};
					}
				};
			}
		};
		mb.createTestModel();
		mb.createTestProcessesAndThreads();
		TargetMethod method = (TargetMethod) mb.testThread1.getCachedAttribute("MyMethod");
		assertEquals(String.class, method.getReturnType());
		assertEquals(TargetParameterMap.ofEntries(
			Map.entry("p1",
				ParameterDescription.create(Integer.class, "p1", true, null, "P1",
					"An int param"))),
			method.getParameters());
		assertEquals("3", waitOn(method.invoke(Map.ofEntries(Map.entry("p1", 3)))));
	}

	@Test
	public void testAnnotatedMethodStringManyArgs() throws Throwable {
		TestDebuggerModelBuilder mb = new TestDebuggerModelBuilder() {
			@Override
			protected TestDebuggerObjectModel newModel(String typeHint) {
				return new TestDebuggerObjectModel(typeHint) {
					@Override
					protected TestTargetThread newTestTargetThread(
							TestTargetThreadContainer container, int tid) {
						return new TestTargetThread(container, tid) {
							{
								changeAttributes(List.of(),
									AnnotatedTargetMethod.collectExports(MethodHandles.lookup(),
										testModel, this),
									"Methods");
							}

							@TargetMethod.Export("MyMethod")
							public CompletableFuture<String> myMethod(
									@TargetMethod.Param(
										display = "I",
										description = "An int param",
										name = "i") int i,
									@TargetMethod.Param(
										display = "B",
										description = "A boolean param",
										name = "b") boolean b,
									@TargetMethod.Param(
										display = "S",
										description = "A string param",
										name = "s") String s,
									@TargetMethod.Param(
										display = "L",
										description = "A long param",
										name = "l") long l) {
								return CompletableFuture
										.completedFuture(i + "," + b + "," + s + "," + l);
							}
						};
					}
				};
			}
		};
		mb.createTestModel();
		mb.createTestProcessesAndThreads();
		TargetMethod method = (TargetMethod) mb.testThread1.getCachedAttribute("MyMethod");
		assertEquals(String.class, method.getReturnType());
		assertEquals(TargetParameterMap.ofEntries(
			Map.entry("i",
				ParameterDescription.create(Integer.class, "i", true, null, "I",
					"An int param")),
			Map.entry("b",
				ParameterDescription.create(Boolean.class, "b", true, null, "B",
					"A boolean param")),
			Map.entry("s",
				ParameterDescription.create(String.class, "s", true, null, "S",
					"A string param")),
			Map.entry("l",
				ParameterDescription.create(Long.class, "l", true, null, "L",
					"A long param"))),
			method.getParameters());
		assertEquals("3,true,Hello,7", waitOn(method.invoke(Map.ofEntries(
			Map.entry("b", true), Map.entry("i", 3), Map.entry("s", "Hello"),
			Map.entry("l", 7L)))));
	}
}
