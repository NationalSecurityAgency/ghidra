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
package ghidra.program.model.lang;

import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

/**
 * <code>InjectPayload</code> encapsulates a semantic (p-code) override which can be injected
 * into analyses that work with p-code (Decompiler, SymbolicPropagator)
 * The payload typically replaces either a subroutine call or a userop
 *
 */
public interface InjectPayload {
	
	public static final int CALLFIXUP_TYPE = 1;
	public static final int CALLOTHERFIXUP_TYPE = 2;
	public static final int CALLMECHANISM_TYPE = 3;
	public static final int EXECUTABLEPCODE_TYPE = 4;

	public static class InjectParameter {
		private String name;
		private int index;
		private int size;
		
		public InjectParameter(String nm,int sz) {
			name = nm;
			index = 0;
			size = sz;
		}
		
		public String getName() {
			return name;
		}

		public int getIndex() {
			return index;
		}
		
		public int getSize() {
			return size;
		}
		
		void setIndex(int i) {
			index = i;
		}
	}

	/**
	 * @return formal name for this injection
	 */
	public String getName();

	/**
	 * @return the type of this injection:  CALLFIXUP_TYPE, CALLMECHANISM_TYPE, etc.
	 */
	public int getType();

	/**
	 * @return a String describing the source of this payload
	 */
	public String getSource();

	/**
	 * @return number of parameters from the original call which should be truncated
	 */
	public int getParamShift();

	/**
	 * @return array of any input parameters for this inject
	 */
	public InjectParameter[] getInput();
	
	/**
	 * @return array of any output parameters for this inject
	 */
	public InjectParameter[] getOutput();
	
	/**
	 * Given a context, send the p-code payload to the emitter
	 * @param context is the context for injection
	 * @param emit is the object accumulating the final p-code
	 */
	public void inject(InjectContext context,PcodeEmit emit);
	
	/**
	 * A convenience function wrapping the inject method, to produce the final set
	 * of PcodeOp objects in an array
	 * @param program is the Program for which injection is happening
	 * @param con is the context for injection
	 * @return the array of PcodeOps
	 */
	public PcodeOp[] getPcode(Program program, InjectContext con);
	
	/**
	 * @return true if the injected p-code falls thru
	 */
	public boolean isFallThru();
}
