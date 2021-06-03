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
package agent.dbgeng.manager.impl;

import static ghidra.async.AsyncUtils.*;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.function.Supplier;

import com.google.common.collect.RangeSet;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugClient.DebugAttachFlags;
import agent.dbgeng.manager.*;
import agent.dbgeng.manager.DbgManager.ExecSuffix;
import agent.dbgeng.manager.cmd.*;
import ghidra.async.TypeSpec;
import ghidra.comm.util.BitmaskSet;
import ghidra.dbg.target.TargetAttachable;
import ghidra.util.Msg;

public class DbgProcessImpl implements DbgProcess {

	private final Map<DebugThreadId, DbgThreadImpl> threads = new LinkedHashMap<>();
	private final Map<DebugThreadId, DbgThread> unmodifiableThreads =
		Collections.unmodifiableMap(threads);

	private final Map<String, DbgModuleImpl> modules = new LinkedHashMap<>();
	private final Map<String, DbgModule> unmodifiableModules = Collections.unmodifiableMap(modules);

	private final NavigableMap<Long, DbgSectionImpl> mappings = new TreeMap<>();
	private final NavigableMap<Long, DbgSectionImpl> unmodifiableMappings =
		Collections.unmodifiableNavigableMap(mappings);

	private DbgManagerImpl manager;
	private DebugProcessId id;
	private Long pid;
	private Long exitCode;

	/**
	 * Construct a new inferior
	 * 
	 * @param manager the manager creating the process
	 * @param id the dbgeng-assigned process ID
	 */
	public DbgProcessImpl(DbgManagerImpl manager, DebugProcessId id, long pid) {
		this.manager = manager;
		this.id = id;
		this.pid = pid;
	}

	public DbgProcessImpl(DbgManagerImpl manager) {
		this.manager = manager;
	}

	@Override
	public String toString() {
		return "<DbgProcess id=" + id + ",pid=" + pid + ",exitCode=" + exitCode + ">";
	}

	@Override
	public DebugProcessId getId() {
		return id;
	}

	public void setId(DebugProcessId id) {
		this.id = id;
	}

	@Override
	public Long getPid() {
		return pid;
	}

	/**
	 * Set the exit code
	 * 
	 * @param exitCode the exit code (status or signal)
	 */
	public void setExitCode(Long exitCode) {
		this.exitCode = exitCode;
	}

	@Override
	public Long getExitCode() {
		return exitCode;
	}

	/**
	 * Add this process to the manager's list of processes, because of a given cause
	 * 
	 * @param cause the cause of the new inferior
	 */
	public void add() {
		manager.processes.put(id, this);
		//manager.getEventListeners().fire.processAdded(this, DbgCause.Causes.UNCLAIMED);
		//manager.addProcess(this, cause);
	}

	/**
	 * Remove this process from the manager's list of processes, because of a given cause
	 * 
	 * @param cause the cause of removal
	 */
	public void remove(DbgCause cause) {
		manager.removeProcess(id, cause);
	}

	@Override
	public CompletableFuture<Void> remove() {
		return manager.removeProcess(this);
	}

	/**
	 * Use {@link DbgThreadImpl#add()} instead
	 * 
	 * @param thread the thread to add
	 */
	public void addThread(DbgThreadImpl thread) {
		DbgThreadImpl exists = threads.get(thread.getId());
		if (exists != null) {
			Msg.warn(this, "Adding pre-existing thread " + exists);
			//throw new IllegalArgumentException("There is already thread " + exists);
		}
		threads.put(thread.getId(), thread);

	}

	@Override
	public DbgThreadImpl getThread(DebugThreadId tid) {
		DbgThreadImpl result = threads.get(tid);
		if (result == null) {
			throw new IllegalArgumentException("There is no thread with id " + tid);
		}
		return result;
	}

	/**
	 * Use {@link DbgThreadImpl#remove()} instead
	 * 
	 * @param tid the ID of the thread to remove
	 */
	public void removeThread(DebugThreadId tid) {
		if (threads.remove(tid) == null) {
			throw new IllegalArgumentException("There is no thread with id " + tid);
		}
	}

	/**
	 * Use {@link DbgModuleImpl#add()} instead
	 * 
	 * @param module the thread to add
	 */
	public void addModule(DbgModuleImpl module) {
		DbgModuleImpl exists = modules.get(module.getInfo().toString());
		if (exists != null) {
			throw new IllegalArgumentException("There is already module " + exists);
		}
		modules.put(module.getInfo().toString(), module);

	}

	@Override
	public DbgModuleImpl getModule(String id) {
		DbgModuleImpl result = modules.get(id);
		if (result == null) {
			throw new IllegalArgumentException("There is no module with id " + id);
		}
		return result;
	}

	/**
	 * Use {@link DbgModulesImpl#remove()} instead
	 * 
	 * @param id the ID of the thread to remove
	 */
	public void removeModule(String id) {
		if (modules.remove(id) == null) {
			throw new IllegalArgumentException("There is no module with id " + id);
		}
	}

	@Override
	public Map<DebugThreadId, DbgThread> getKnownThreads() {
		return unmodifiableThreads;
	}

	public Map<DebugThreadId, DbgThreadImpl> getKnownThreadsImpl() {
		return threads;
	}

	@Override
	public CompletableFuture<Map<DebugThreadId, DbgThread>> listThreads() {
		return manager.execute(new DbgListThreadsCommand(manager, this));
	}

	@Override
	public Map<String, DbgModule> getKnownModules() {
		return unmodifiableModules;
	}

	@Override
	public CompletableFuture<Map<String, DbgModule>> listModules() {
		return manager.execute(new DbgListModulesCommand(manager, this));
	}

	@Override
	public Map<Long, DbgSectionImpl> getKnownMappings() {
		return unmodifiableMappings;
	}

	@Override
	public CompletableFuture<Map<Long, DbgSectionImpl>> listMappings() {
		return manager.execute(new DbgListMappingsCommand(manager, this));
	}

	@Override
	public CompletableFuture<Void> setActive() {
		return manager.setActiveProcess(this);
	}

	@Override
	public CompletableFuture<Void> fileExecAndSymbols(String file) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			setActive().handle(seq::next);
		}).then((seq) -> {
			manager.execute(new DbgFileExecAndSymbolsCommand(manager, file)).handle(seq::exit);
		}).finish();
	}

	@Override
	public CompletableFuture<DbgThread> run() {
		return sequence(TypeSpec.cls(DbgThread.class)).then((seq) -> {
			setActive().handle(seq::next);
		}).then((seq) -> {
			manager.execute(new DbgRunCommand(manager)).handle(seq::exit);
		}).finish();
	}

	@Override
	public CompletableFuture<Set<DbgThread>> attach(long toPid) {
		return sequence(TypeSpec.cls(DbgThread.class).set()).then((seq) -> {
			setActive().handle(seq::next);
		}).then((seq) -> {
			pid = toPid; // TODO: Wait for successful completion?
			manager.execute(
				new DbgAttachCommand(manager, this, BitmaskSet.of(DebugAttachFlags.DEFAULT)))
					.handle(seq::exit);
		}).finish();
	}

	@Override
	public CompletableFuture<Set<DbgThread>> reattach(TargetAttachable attachable) {
		return sequence(TypeSpec.cls(DbgThread.class).set()).then((seq) -> {
			setActive().handle(seq::next);
		}).then((seq) -> {
			manager.execute(
				new DbgAttachCommand(manager, this, BitmaskSet.of(DebugAttachFlags.EXISTING)))
					.handle(seq::exit);
		}).finish();
	}

	@Override
	public CompletableFuture<Void> detach() {
		return sequence(TypeSpec.VOID).then((seq) -> {
			setActive().handle(seq::next);
		}).then((seq) -> {
			manager.execute(new DbgDetachCommand(manager, this)).handle(seq::exit);
		}).finish();
	}

	@Override
	public CompletableFuture<Void> kill() {
		return sequence(TypeSpec.VOID).then((seq) -> {
			setActive().handle(seq::next);
		}).then((seq) -> {
			manager.execute(new DbgKillCommand(manager)).handle(seq::exit);
		}).finish();
	}

	@Override
	public CompletableFuture<Void> cont() {
		return sequence(TypeSpec.VOID).then((seq) -> {
			setActive().handle(seq::next);
		}).then((seq) -> {
			manager.execute(new DbgContinueCommand(manager)).handle(seq::exit);
		}).finish();
	}

	@Override
	public CompletableFuture<Void> step(ExecSuffix suffix) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			setActive().handle(seq::next);
		}).then((seq) -> {
			manager.execute(new DbgStepCommand(manager, null, suffix)).handle(seq::exit);
		}).finish();
	}

	@Override
	public CompletableFuture<Void> step(Map<String, ?> args) {
		return sequence(TypeSpec.VOID).then((seq) -> {
			setActive().handle(seq::next);
		}).then((seq) -> {
			manager.execute(new DbgStepCommand(manager, null, args)).handle(seq::exit);
		}).finish();
	}

	protected <T> CompletableFuture<T> preferThread(
			Function<DbgThreadImpl, CompletableFuture<T>> viaThread,
			Supplier<CompletableFuture<T>> viaThis) {
		Optional<DbgThreadImpl> first = threads.values().stream().findFirst();
		if (first.isPresent()) {
			return viaThread.apply(first.get());
		}
		return setActive().thenCompose(__ -> viaThis.get());
	}

	@Override
	public CompletableFuture<RangeSet<Long>> readMemory(long addr, ByteBuffer buf, int len) {
		// I can't imagine this working without a thread....
		return preferThread(t -> t.readMemory(addr, buf, len),
			() -> manager.execute(new DbgReadMemoryCommand(manager, addr, buf, len)));
	}

	@Override
	public CompletableFuture<Void> writeMemory(long addr, ByteBuffer buf, int len) {
		// I can't imagine this working without a thread....
		return preferThread(t -> t.writeMemory(addr, buf, len),
			() -> manager.execute(new DbgWriteMemoryCommand(manager, addr, buf, len)));
	}

	@Override
	public CompletableFuture<String> consoleCapture(String command) {
		// TODO Auto-generated method stub
		return null;
	}

	protected void moduleLoaded(DebugModuleInfo info) {
		if (!modules.containsKey(info.getModuleName())) {
			DbgModuleImpl module = new DbgModuleImpl(manager, this, info);
			modules.put(info.toString(), module);
		}
	}

	protected void moduleUnloaded(DebugModuleInfo info) {
		modules.remove(info.toString());
	}

	protected void threadCreated(DbgThreadImpl thread) {
		threads.put(thread.getId(), thread);
	}

	public void threadExited(DebugThreadId id) {
		threads.remove(id);
	}

	@Override
	public CompletableFuture<String> evaluate(String expression) {
		return manager.execute(new DbgEvaluateCommand(manager, expression));
	}
}
