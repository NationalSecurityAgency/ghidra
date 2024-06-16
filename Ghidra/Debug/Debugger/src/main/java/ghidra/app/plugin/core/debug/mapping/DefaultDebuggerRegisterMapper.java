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

import java.util.*;

import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.target.TargetRegisterContainer;
import ghidra.debug.api.model.DebuggerRegisterMapper;
import ghidra.program.model.lang.*;

public class DefaultDebuggerRegisterMapper implements DebuggerRegisterMapper {
	protected final Language language;
	protected final CompilerSpec cspec;
	//protected final TargetRegisterContainer targetRegContainer;
	protected final boolean caseSensitive;

	protected final Map<String, Register> languageRegs = new LinkedHashMap<>();
	protected final Map<String, Register> filtLanguageRegs = new LinkedHashMap<>();
	protected final Map<String, TargetRegister> targetRegs = new HashMap<>();

	public DefaultDebuggerRegisterMapper(CompilerSpec cSpec,
			TargetRegisterContainer targetRegContainer, boolean caseSensitive) {
		this.language = cSpec.getLanguage();
		this.cspec = cSpec;
		//this.targetRegContainer = targetRegContainer;
		this.caseSensitive = caseSensitive;

		collectFilteredLanguageRegs();
	}

	protected boolean includeTraceRegister(Register lReg) {
		return lReg.isBaseRegister();
	}

	protected synchronized void collectFilteredLanguageRegs() {
		for (Register lReg : language.getRegisters()) {
			if (!includeTraceRegister(lReg)) {
				continue;
			}
			putLanguageRegister(filtLanguageRegs, lReg);
		}
	}

	protected synchronized void putLanguageRegister(Map<String, Register> map, Register lReg) {
		map.put(normalizeName(lReg.getName()), lReg);
		for (String alias : lReg.getAliases()) {
			map.put(normalizeName(alias), lReg);
		}
	}

	protected synchronized void removeLanguageRegister(Map<String, Register> map, Register lReg) {
		map.remove(normalizeName(lReg.getName()));
		for (String alias : lReg.getAliases()) {
			map.remove(normalizeName(alias));
		}
	}

	protected synchronized Register considerRegister(String index) {
		String name = normalizeName(index);
		Register lReg = filtLanguageRegs.get(name);
		if (lReg == null) {
			return null;
		}
		putLanguageRegister(languageRegs, lReg);
		return lReg;
	}

	protected synchronized Register considerRegister(TargetRegister tReg) {
		String name = normalizeName(tReg.getIndex());
		Register lReg = filtLanguageRegs.get(name);
		if (lReg == null) {
			return null;
		}
		targetRegs.put(name, tReg);
		putLanguageRegister(languageRegs, lReg);
		return lReg;
	}

	protected synchronized Register removeRegister(TargetRegister tReg) {
		String name = normalizeName(tReg.getIndex());
		Register lReg = filtLanguageRegs.get(name);
		if (lReg == null) {
			return null;
		}
		targetRegs.remove(name);
		removeLanguageRegister(languageRegs, lReg);
		return lReg;
	}

	protected String normalizeName(String name) {
		if (caseSensitive) {
			return name;
		}
		return name.toLowerCase();
	}

	@Override
	public synchronized TargetRegister getTargetRegister(String name) {
		return targetRegs.get(normalizeName(name));
	}

	@Override
	public synchronized Register getTraceRegister(String name) {
		return languageRegs.get(normalizeName(name));
	}

	@Override
	public synchronized TargetRegister traceToTarget(Register lReg) {
		TargetRegister tReg = targetRegs.get(normalizeName(lReg.getName()));
		if (tReg != null) {
			return tReg;
		}
		for (String alias : lReg.getAliases()) {
			tReg = targetRegs.get(normalizeName(alias));
			if (tReg != null) {
				return tReg;
			}
		}
		return null;
	}

	@Override
	public synchronized Register targetToTrace(TargetRegister tReg) {
		return languageRegs.get(normalizeName(tReg.getIndex()));
	}

	@Override
	public synchronized Set<Register> getRegistersOnTarget() {
		return Set.copyOf(languageRegs.values());
	}

	@Override
	public synchronized void targetRegisterAdded(TargetRegister register) {
		//if (!PathUtils.isAncestor(targetRegContainer.getPath(), register.getPath())) {
		//	return;
		//}
		considerRegister(register);
	}

	@Override
	public synchronized void targetRegisterRemoved(TargetRegister register) {
		//if (!PathUtils.isAncestor(targetRegContainer.getPath(), register.getPath())) {
		//	return;
		//}
		removeRegister(register);
	}
}
