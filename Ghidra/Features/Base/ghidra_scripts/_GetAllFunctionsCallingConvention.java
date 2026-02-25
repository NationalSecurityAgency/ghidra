
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

// Script to export ALL function definitions for the @currentProgram
//@category Export
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;

public class _GetAllFunctionsCallingConvention extends GhidraScript {

	private BufferedWriter fileWriter;

	@Override
	public void run() throws Exception {

		if (currentProgram != null) {
			String DIR = "D:/";
			String filename = DIR + currentProgram.getName() + "FunctionSpecs.tab";
System.out.println(filename);
			fileWriter = new BufferedWriter(new FileWriter(filename));

			FunctionManager fnMgr = currentProgram.getFunctionManager();
			if (fnMgr == null) {
				return;
			}

			// update details
			doRun(fnMgr.getFunctions(true));

			fileWriter.close();
		}
	}

	/**
	 * @param functions
	 */
	private void doRun(Iterator<Function> functions) {
		while (functions.hasNext()) {
			if ((getMonitor() != null) && getMonitor().isCancelled()) {
				return;
			}

			doRun(functions.next());
		}
	}

	/**
	 * Do for individually identified function
	 *
	 * @param func this function
	 */
	protected void doRun(Function func) {

		final String SEP = "\t";
		try {
			fileWriter.write(func.getBody().getMinAddress() + SEP + func.getName(true)
					+ SEP + func.getCallingConventionName()
					+ SEP + getDescription(func));
			fileWriter.newLine();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * @param f Function object
	 * @return string to print out
	 */
	private static String getDescription(Function f) {
		StringBuilder s = new StringBuilder();
		String szSep = "";
		s.append(f.getReturnType().getName()).append(' ');
		s.append(f.getName(true)).append(" (");
		for (int i = 0; i < f.getParameters().length; i++) {
			Parameter p = f.getParameter(i);
			s.append(szSep).append(p.getFormalDataType().getName()).append(' ').append(p.getName());
			//s.append("[").append(p.getLastStorageVarnode().toString()).append("]");
			szSep = ", ";
		}
		s.append(')');
		return s.toString();
	}

}
