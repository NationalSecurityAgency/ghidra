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
package ghidra.app.plugin.core.debug.mapping;

import java.util.Collection;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.core.debug.service.model.DebuggerModelServicePlugin;
import ghidra.app.plugin.core.debug.service.model.DefaultTraceRecorder;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.target.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.trace.model.Trace;

public class DefaultDebuggerTargetTraceMapper implements DebuggerTargetTraceMapper {
	protected final TargetObject target;
	protected final Language language;
	protected final CompilerSpec cSpec;

	protected final Set<String> extraRegNames;

	public DefaultDebuggerTargetTraceMapper(TargetObject target, LanguageID langID,
			CompilerSpecID csId, Collection<String> extraRegNames)
			throws LanguageNotFoundException, CompilerSpecNotFoundException {
		this.target = target;
		LanguageService langServ = DefaultLanguageService.getLanguageService();
		this.language = langServ.getLanguage(langID);
		this.cSpec = language.getCompilerSpecByID(csId);

		this.extraRegNames = Set.copyOf(extraRegNames);
	}

	/**
	 * Create a mapper between trace and target memory
	 * 
	 * <p>
	 * TODO: Now that every impl just uses the model's address factory, we should probably just have
	 * this take a model, and create the mapper in the recorder's constructor.
	 * 
	 * @param memory the target memory
	 * @return the mapper
	 */
	protected DebuggerMemoryMapper createMemoryMapper(TargetMemory memory) {
		return new DefaultDebuggerMemoryMapper(language, memory.getModel());
	}

	/**
	 * Create a mapper between trace and target registers
	 * 
	 * @param registers the target's register container
	 * @return the mapper
	 */
	protected DebuggerRegisterMapper createRegisterMapper(TargetRegisterContainer registers) {
		return new DefaultDebuggerRegisterMapper(cSpec, registers, false);
	}

	// TODO: Make this synchronous, or remove it
	public CompletableFuture<DebuggerMemoryMapper> offerMemory(TargetMemory memory) {
		DebuggerMemoryMapper mm = createMemoryMapper(memory);
		return CompletableFuture.completedFuture(mm);
	}

	// TODO: Make this synchronous, or remove it
	public CompletableFuture<DebuggerRegisterMapper> offerRegisters(
			TargetRegisterContainer registers) {
		DebuggerRegisterMapper rm = createRegisterMapper(registers);
		return CompletableFuture.completedFuture(rm);
	}

	public Set<String> getExtraRegNames() {
		return extraRegNames;
	}

	@Override
	public Language getTraceLanguage() {
		return language;
	}

	@Override
	public CompilerSpec getTraceCompilerSpec() {
		return cSpec;
	}

	@Override
	public TraceRecorder startRecording(DebuggerModelServicePlugin service, Trace trace) {
		return new DefaultTraceRecorder(service, trace, target, this);
	}
}
