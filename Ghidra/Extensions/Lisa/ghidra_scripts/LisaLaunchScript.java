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

//Template for running analyses using Lisa (does very little, as is)
//@category PCode

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.lisa.pcode.PcodeFrontend;
import ghidra.lisa.pcode.analyses.PcodeByteBasedConstantPropagation;
import ghidra.lisa.pcode.locations.PcodeLocation;
import ghidra.util.Msg;
import it.unive.lisa.*;
import it.unive.lisa.analysis.*;
import it.unive.lisa.analysis.nonrelational.value.ValueEnvironment;
import it.unive.lisa.interprocedural.InterproceduralAnalysis;
import it.unive.lisa.program.Program;
import it.unive.lisa.program.cfg.CFG;
import it.unive.lisa.program.cfg.statement.Statement;
import it.unive.lisa.symbolic.value.Identifier;
import it.unive.lisa.util.representation.StructuredRepresentation;

public class LisaLaunchScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (isRunningHeadless()) {
			popup("Script is not running in GUI");
			return;
		}

		PcodeFrontend frontend = new PcodeFrontend(state.getTool());
		Program p = frontend.doWork(currentProgram.getListing(), currentAddress, false);

		DefaultConfiguration conf = new DefaultConfiguration();
		conf.serializeResults = true;
		conf.abstractState = DefaultConfiguration.simpleState(
			DefaultConfiguration.defaultHeapDomain(),
			//new DefiniteDataflowDomain<>(new ConstantPropagation()),
			new ValueEnvironment<>(
				new PcodeByteBasedConstantPropagation(currentProgram.getLanguage())),
			DefaultConfiguration.defaultTypeDomain());
		LiSA lisa = new LiSA(conf);

		LiSAReport report = lisa.run(p);
		InterproceduralAnalysis<?> interproceduralAnalysis =
			report.getConfiguration().interproceduralAnalysis;
		Collection<CFG> ep = p.getEntryPoints();
		for (CFG cfg : ep) {
			Collection<?> results = interproceduralAnalysis.getAnalysisResultsOf(cfg);
			Iterator<?> iterator = results.iterator();
			while (iterator.hasNext()) {
				Object next = iterator.next();
				if (next instanceof AnalyzedCFG<?> acfg) {
					processCFG(cfg, acfg);
				}
			}
		}

	}

	private void processCFG(CFG cfg, AnalyzedCFG<?> acfg) {
		if (!cfg.getNodes().isEmpty()) {
			for (Statement st : cfg.getNodes()) {
				AnalysisState<?> s = acfg.getAnalysisStateAfter(st);
				AbstractState<?> abs = s.getState();
				if (abs instanceof SimpleAbstractState sas) {
					processState(sas, st);
				}
			}
		}
	}

	@SuppressWarnings("rawtypes")
	private void processState(SimpleAbstractState sas, Statement st) {
		ValueEnvironment<?> valueState =
			(ValueEnvironment<?>) sas.getValueState();
		//DefiniteDataflowDomain valueState = (DefiniteDataflowDomain) sas.getValueState();
		Map<Identifier, ?> function = valueState.function;
		if (function != null) {
			for (Object key : function.keySet()) {
				Object val = valueState.function.get(key);
				exampleAnalysis(st, key, val);
			}
		}
	}

	private void exampleAnalysis(Statement st, Object key, Object val) {
		if (val instanceof PcodeByteBasedConstantPropagation icp) {
			StructuredRepresentation representation =
				icp.representation();
			String rep = representation.toString();
			if (!rep.contains("TOP")) {
				PcodeLocation loc =
					(PcodeLocation) st.getLocation();
				Msg.info(this, loc.getCodeLocation() +
					" ==> " + key + ":" + representation);
			}
		}
	}

}
