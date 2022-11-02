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
package ghidra.dbg.model;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.*;

import org.jdom.JDOMException;

import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.attributes.TargetDataType;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;

// TODO: Refactor with other Fake and Test model stuff.
public class TestDebuggerObjectModel extends EmptyDebuggerObjectModel {
	public static final String TEST_MODEL_STRING = "Test Model";
	protected static final int DELAY_MILLIS = 250;

	// TODO: Should this be tunable?
	public static final Executor DELAYED_EXECUTOR =
		CompletableFuture.delayedExecutor(DELAY_MILLIS, TimeUnit.MILLISECONDS);

	enum FutureMode {
		ASYNC, DELAYED;
	}

	public static final XmlSchemaContext SCHEMA_CTX;
	public static final TargetObjectSchema ROOT_SCHEMA;
	static {
		try {
			SCHEMA_CTX = XmlSchemaContext.deserialize(
				EmptyDebuggerObjectModel.class.getResourceAsStream("test_schema.xml"));
			ROOT_SCHEMA = SCHEMA_CTX.getSchema(SCHEMA_CTX.name("Test"));
		}
		catch (IOException | JDOMException e) {
			throw new AssertionError(e);
		}
	}

	public final TestTargetSession session;

	protected int invalidateCachesCount;

	public TestDebuggerObjectModel() {
		this("Session");
	}

	public TestDebuggerObjectModel(String rootHint) {
		this.session = newTestTargetSession(rootHint);
		addModelRoot(session);
	}

	protected TestTargetSession newTestTargetSession(String rootHint) {
		return new TestTargetSession(this, rootHint, ROOT_SCHEMA);
	}

	protected TestTargetEnvironment newTestTargetEnvironment(TestTargetSession session) {
		return new TestTargetEnvironment(session);
	}

	protected TestTargetProcessContainer newTestTargetProcessContainer(TestTargetSession session) {
		return new TestTargetProcessContainer(session);
	}

	protected TestTargetProcess newTestTargetProcess(TestTargetProcessContainer container, int pid,
			AddressSpace space) {
		return new TestTargetProcess(container, pid, space);
	}

	protected TestTargetBreakpointContainer newTestTargetBreakpointContainer(
			TestTargetProcess process) {
		return new TestTargetBreakpointContainer(process);
	}

	protected TestTargetBreakpoint newTestTargetBreakpoint(TestTargetBreakpointContainer container,
			int num, AddressRange range, Set<TargetBreakpointKind> kinds) {
		return new TestTargetBreakpoint(container, num, range, kinds);
	}

	protected TestTargetMemory newTestTargetMemory(TestTargetProcess process, AddressSpace space) {
		return new TestTargetMemory(process, space);
	}

	protected TestTargetMemoryRegion newTestTargetMemoryRegion(TestTargetMemory memory, String name,
			AddressRange range, String flags) {
		return new TestTargetMemoryRegion(memory, name, range, flags);
	}

	protected TestTargetModuleContainer newTestTargetModuleContainer(TestTargetProcess process) {
		return new TestTargetModuleContainer(process);
	}

	protected TestTargetModule newTestTargetModule(TestTargetModuleContainer container, String name,
			AddressRange range) {
		return new TestTargetModule(container, name, range);
	}

	protected TestTargetSectionContainer newTestTargetSectionContainer(TestTargetModule module) {
		return new TestTargetSectionContainer(module);
	}

	protected TestTargetSection newTestTargetSection(TestTargetSectionContainer container,
			String name, AddressRange range) {
		return new TestTargetSection(container, name, range);
	}

	protected TestTargetSymbolNamespace newTestTargetSymbolNamespace(TestTargetModule module) {
		return new TestTargetSymbolNamespace(module);
	}

	protected TestTargetSymbol newTestTargetSymbol(TestTargetSymbolNamespace namespace, String name,
			Address address, long size, TargetDataType dataType) {
		return new TestTargetSymbol(namespace, name, address, size, dataType);
	}

	protected TestTargetDataTypeNamespace newTestTargetDataTypeNamespace(TestTargetModule module) {
		return new TestTargetDataTypeNamespace(module);
	}

	protected TestTargetTypedefDataType newTestTargetTypedefDataType(
			TestTargetDataTypeNamespace namespace, String name, TargetDataType defDataType) {
		return new TestTargetTypedefDataType(namespace, name, defDataType);
	}

	protected TestTargetTypedefDef newTestTargetTypedefDef(TestTargetTypedefDataType typedef,
			TargetDataType dataType) {
		return new TestTargetTypedefDef(typedef, dataType);
	}

	protected TestTargetRegisterContainer newTestTargetRegisterContainer(
			TestTargetProcess process) {
		return new TestTargetRegisterContainer(process);
	}

	protected TestTargetRegister newTestTargetRegister(TestTargetRegisterContainer container,
			Register register) {
		return TestTargetRegister.fromLanguageRegister(container, register);
	}

	protected TestTargetThreadContainer newTestTargetThreadContainer(TestTargetProcess process) {
		return new TestTargetThreadContainer(process);
	}

	protected TestTargetThread newTestTargetThread(TestTargetThreadContainer container, int tid) {
		return new TestTargetThread(container, tid);
	}

	protected TestTargetRegisterBankInThread newTestTargetRegisterBankInThread(
			TestTargetThread thread) {
		return new TestTargetRegisterBankInThread(thread);
	}

	protected TestTargetStack newTestTargetStack(TestTargetThread thread) {
		return new TestTargetStack(thread);
	}

	protected TestTargetStackFrameNoRegisterBank newTestTargetStackFrameNoRegisterBank(
			TestTargetStack stack, int level, Address pc) {
		return new TestTargetStackFrameNoRegisterBank(stack, level, pc);
	}

	protected TestTargetStackFrameHasRegisterBank newTestTargetStackFrameHasRegisterBank(
			TestTargetStack stack, int level, Address pc) {
		return new TestTargetStackFrameHasRegisterBank(stack, level, pc);
	}

	protected TestTargetRegisterBankInFrame newTestTargetRegisterBankInFrame(
			TestTargetStackFrameHasRegisterBank frame) {
		return new TestTargetRegisterBankInFrame(frame);
	}

	protected TestTargetStackFrameIsRegisterBank newTestTargetStackFrameIsRegisterBank(
			TestTargetStack stack, int level, Address pc) {
		return new TestTargetStackFrameIsRegisterBank(stack, level, pc);
	}

	protected TestTargetInterpreter newTestTargetInterpreter(TestTargetSession session) {
		return new TestTargetInterpreter(session);
	}

	protected TestMimickJavaLauncher newTestMimickJavaLauncher(TestTargetSession session) {
		return new TestMimickJavaLauncher(session);
	}

	public Executor getClientExecutor() {
		return clientExecutor;
	}

	@Override
	public TargetObjectSchema getRootSchema() {
		return ROOT_SCHEMA;
	}

	@Override
	public String toString() {
		return TEST_MODEL_STRING;
	}

	@Override // TODO: Give test writer control of addModelRoot
	public CompletableFuture<? extends TargetObject> fetchModelRoot() {
		return future(session);
	}

	@Override
	public CompletableFuture<Void> close() {
		session.invalidateSubtree(session, "Model closed");
		return future(null).thenCompose(__ -> super.close());
	}

	public TestTargetProcess addProcess(int pid) {
		return addProcess(pid, ram);
	}

	public TestTargetProcess addProcess(int pid, AddressSpace space) {
		return session.addProcess(pid, space);
	}

	public void removeProcess(TestTargetProcess process) {
		session.removeProcess(process);
	}

	public <T> CompletableFuture<T> future(T t) {
		return CompletableFuture.supplyAsync(() -> t, getClientExecutor());
	}

	public CompletableFuture<Void> requestFocus(TargetObject obj) {
		return session.requestFocus(obj);
	}

	@Override
	public synchronized void invalidateAllLocalCaches() {
		invalidateCachesCount++;
	}

	public synchronized int clearInvalidateCachesCount() {
		int result = invalidateCachesCount;
		invalidateCachesCount = 0;
		return result;
	}

	public DebuggerModelListener fire() {
		return listeners.fire;
	}
}
