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
package ghidra.app.plugin.core.decompiler.taint.ctadl;

import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.List;

import generic.jar.ResourceFile;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompiler.taint.*;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin.TaintDirection;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.*;
import ghidra.app.services.ConsoleService;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighVariable;

/**
 * Container for all the decompiler elements the users "selects" via the menu.
 * This data is used to build queries.
 */
public class CTADLTaintState extends AbstractTaintState {

	public CTADLTaintState(TaintPlugin plugin) {
		super(plugin);
		ENGINE_NAME = "ctadl";
	}

	@Override
	public void buildQuery(List<String> paramList, Path engine, File indexDBFile,
			String indexDirectory) {
		paramList.add(engine.toString());
		paramList.add("--directory");
		paramList.add(indexDirectory);
		paramList.add("query");
		Comparable<TaintDirection> direction = taintOptions.getTaintDirection();
		if (!direction.equals(TaintDirection.DEFAULT)) {
			paramList.add("--compute-slices");
			switch (taintOptions.getTaintDirection()) {
				case TaintDirection.BOTH ->
					paramList.add("all");
				case TaintDirection.FORWARD ->
					paramList.add("fwd");
				case TaintDirection.BACKWARD ->
					paramList.add("bwd");
				default -> {
					// No action
				}
			}
		}
		paramList.add("--no-compile-analysis");
		paramList.add("-j8");
		paramList.add("--format=" + taintOptions.getTaintOutputForm().toString());
	}

	@Override
	public void buildIndex(List<String> paramList, String engine_path, String facts_path,
			String indexDirectory) {
		paramList.add(engine_path);
		paramList.add("--directory");
		paramList.add(indexDirectory);
		paramList.add("index");
		paramList.add("-j8");
		paramList.add("-f");
		paramList.add(facts_path);
	}

	@Override
	public GhidraScript getExportScript(ConsoleService console, boolean perFunction) {
		String scriptName = getScriptName(perFunction);
		BundleHost bundleHost = GhidraScriptUtil.acquireBundleHostReference();
		for (ResourceFile dir : bundleHost.getBundleFiles()) {
			if (dir.isDirectory()) {
				ResourceFile scriptFile = new ResourceFile(dir, scriptName);
				if (scriptFile.exists()) {
					GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
					try {
						return provider.getScriptInstance(scriptFile, console.getStdErr());
					}
					catch (GhidraScriptLoadException e) {
						console.addErrorMessage("", "Unable to load script: " + scriptName);
						console.addErrorMessage("", "  detail: " + e.getMessage());
					}
				}
			}
		}
		throw new IllegalArgumentException("Script does not exist: " + scriptName);
	}

	protected String getScriptName(boolean perFunction) {
		return perFunction ? "ExportPCodeForSingleFunction.java" : "ExportPCodeForCTADL.java";
	}


	@Override
	protected void writeHeader(PrintWriter writer) {
		writer.println("#include \"pcode/taintquery.dl\"");
	}
	
	/*
	 * NOTE: This is the only method used now for Sources and Sinks.
	 */
	@Override
	protected void writeRule(PrintWriter writer, TaintLabel mark, boolean isSource) {
		Boolean allAccess = taintOptions.getTaintUseAllAccess();
		String method = isSource ? "TaintSource" : "LeakingSink";
		Address addr = mark.getAddress();
		boolean functionLevel = mark.getVarnodeAddress() == null;

		if (mark.getFunctionName() == null) {
			return;
		}

		ClangToken token = mark.getToken();
		if (token instanceof ClangFuncNameToken) {

			writer.println(method + "Vertex(\"" + mark.getLabel() + "\", vn, p) :-");
			writer.println("\tHFUNC_NAME(f, \"" + mark.getFunctionName() + "\"),");
			writer.println("\tCFunction_FormalParam(f, n, vn),");
			writer.println("\tCReturnParameter(n),");
			writer.println("\tVertex(vn, p).");

		}
		else {

			HighVariable hv = mark.getHighVariable();
			String pathConstraint = null;
			if (hv == null && token instanceof ClangFieldToken ftoken) {
				ClangVariableToken vtoken = TaintState.getParentToken(ftoken);
				if (vtoken != null) {
					hv = vtoken.getHighVariable();
					pathConstraint = token.getText();
					token = vtoken;
				}
			}
			writer.println(method + "Vertex(\"" + mark.getLabel() + "\", vn, p) :-");
			writer.println("\t((HFUNC_NAME(m, \"" + mark.getFunctionName() + "\"),");
			writer.println("\tCVar_InFunction(vn, m)) ; CVar_isGlobal(vn)),");
			if (!functionLevel && !mark.bySymbol()) {
				writer.println("\t(PCODE_INPUT(i, _, vn) ; PCODE_OUTPUT(i, vn)),");
				writer.println("\tPCODE_TARGET(i, " + addr.getOffset() + "),");
			}
			if (mark.bySymbol() && hv != null) {
				writer.println("\t((SYMBOL_NAME(sym, \"" + token.getText() + "\"),");
				writer.println("\tSYMBOL_HVAR(sym, hv),");
				// Note this is an OR
				writer.println("\tVNODE_HVAR(vn, hv));");
				writer.println("\tCVar_SourceInfo(vn, SOURCE_INFO_NAME_KEY, \"" +
				TaintState.varName(token, false) + "\")),");
			} else if (mark.bySymbol()) {
				writer.println("\tSYMBOL_NAME(sym, \"" + token.getText() + "\"),");
				writer.println("\tSYMBOL_HVAR(sym, hv),");
				writer.println("\tVNODE_HVAR(vn, hv),");
			}
			else if (hv != null) {
				writer.println("\tCVar_SourceInfo(vn, SOURCE_INFO_NAME_KEY, \"" +
					TaintState.varName(token, false) + "\"),");
			}
			else {
				writer.println("\t(CVar_SourceInfo(vn, SOURCE_INFO_NAME_KEY, \"" +
				TaintState.varName(token, false) + "\");");
			}
			if (pathConstraint != null) {
				writer.println("\tp = \"."+pathConstraint+"\",");
			}
			if (!allAccess) {
				writer.println("\tp = \"\",");
			}
			writer.println("\tVertex(vn, p).");

		}
	}

	@Override
	public void writeGate(PrintWriter writer, TaintLabel mark) {
		Boolean allAccess = taintOptions.getTaintUseAllAccess();
		String method = "TaintSanitizeAll";
		Address addr = mark.getAddress();
		// TODO: verify setting entryPoint as addr doesn't break things

		if (mark.getFunctionName() == null) {
			return;
		}

		writer.println(method + "Vertex(vn, p) :-");
		if (!mark.isGlobal()) {
			writer.println("\tHFUNC_NAME(m, \"" + mark.getFunctionName().toString() + "\"),");
			writer.println("\tCVar_InFunction(vn, m),");
		}
		if (addr != null && addr.getOffset() != 0) {
			writer.println("\tVNODE_PC_ADDRESS(vn, " + addr.getOffset() + "),");
		}
		writer.println("\tCVar_SourceInfo(vn, SOURCE_INFO_NAME_KEY, \"" +
			TaintState.varName(mark.getToken(), false) + "\"),");
		if (!allAccess) {
			writer.println("\tp = \"\",");
		}
		writer.println("\tVertex(vn, p).");
	}

	@Override
	protected void writeFooter(PrintWriter writer) {
		// Nothing to do here
	}

}
