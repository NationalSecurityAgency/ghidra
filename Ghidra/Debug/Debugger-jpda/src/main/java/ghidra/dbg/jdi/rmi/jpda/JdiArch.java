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
package ghidra.dbg.jdi.rmi.jpda;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.core.debug.client.tracermi.DefaultMemoryMapper;
import ghidra.app.plugin.core.debug.client.tracermi.DefaultRegisterMapper;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;

public class JdiArch {

	private JdiConnector connector;
	private LanguageID langID;
	private Language language;

	private final LanguageService languageService = DefaultLanguageService.getLanguageService();

	public JdiArch(JdiConnector connector) {
		this.connector = connector;
	}

	public String getArch() {
		Map<String, String> env = new HashMap<>(connector.getEnv());
		String arch = "JVM";
		if (env.containsKey("OPT_ARCH")) {
			arch = env.get("OPT_ARCH");
		}
		return arch.equals("Dalvik") ? "Dalvik" : "JVM";
	}

	public String getEndian() {
		return "big";
	}

	public String getOSABI() {
		Map<String, String> env = new HashMap<>(connector.getEnv());
		String arch = "JVM";
		if (env.containsKey("OPT_ARCH")) {
			arch = env.get("OPT_ARCH");
		}
		return arch.equals("Dalvik") ? "Dalvik:LE:32:default" : "JVM:BE:32:default";
	}

	public LanguageID computeGhidraLanguage() {
		return new LanguageID(getOSABI());
	}

	public CompilerSpecID computeGhidraCompiler(LanguageID id) {
		return new CompilerSpecID("default");
	}

	public void computeGhidraLcsp() {
		langID = computeGhidraLanguage();
		try {
			language = languageService.getLanguage(langID);
		}
		catch (LanguageNotFoundException e) {
			throw new RuntimeException(e);
		}
	}

	public DefaultMemoryMapper computeMemoryMapper() {
		if (langID == null) {
			computeGhidraLcsp();
		}
		return new DefaultMemoryMapper(langID);
	}

	public DefaultRegisterMapper computeRegisterMapper() {
		if (langID == null) {
			computeGhidraLcsp();
		}
		return new DefaultRegisterMapper(langID);
	}

	public Language getLanguage() {
		return language;
	}

}
