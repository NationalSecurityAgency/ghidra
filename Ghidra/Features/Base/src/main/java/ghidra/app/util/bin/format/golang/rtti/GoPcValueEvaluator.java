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
package ghidra.app.util.bin.format.golang.rtti;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.LEB128;

/**
 * Evaluates a sequence of (value_delta,pc_delta) leb128 pairs to calculate a value for a certain 
 * PC location. 
 */
public class GoPcValueEvaluator {
	private final int pcquantum;
	private final long funcEntry;
	private final BinaryReader reader;

	private int value = -1;
	private long pc;

	/**
	 * Creates a {@link GoPcValueEvaluator} instance, tied to the specified GoFuncData, starting
	 * at the specified offset in the moduledata's pctab.
	 * 
	 * @param func {@link GoFuncData}
	 * @param offset offset in moduledata's pctab
	 * @throws IOException if error reading pctab
	 */
	public GoPcValueEvaluator(GoFuncData func, long offset) throws IOException {
		GoModuledata moduledata = func.getModuledata();
		
		this.pcquantum = moduledata.getGoBinary().getMinLC();
		this.reader = moduledata.getPctab().getElementReader(1, (int) offset);

		this.funcEntry = func.getFuncAddress().getOffset();
		this.pc = funcEntry;
	}

	/**
	 * Returns the largest PC value calculated when evaluating the result of the table's sequence.
	 * 
	 * @return largest PC value encountered
	 * @throws IOException if error evaluating result
	 */
	public long getMaxPC() throws IOException {
		eval(Long.MAX_VALUE);
		return pc;
	}

	/**
	 * Returns the value encoded into the table at the specified pc.
	 * 
	 * @param targetPC pc
	 * @return value at specified pc, or -1 if error evaluating table
	 * @throws IOException if error reading data
	 */
	public int eval(long targetPC) throws IOException {
		while (pc <= targetPC) {
			if (!step()) {
				return -1;
			}
		}
		return value;
	}

	/**
	 * Returns the set of all values for each unique pc section.
	 * 
	 * @param targetPC max pc to advance the sequence to when evaluating the table 
	 * @return list of integer values
	 * @throws IOException if error reading data
	 */
	public List<Integer> evalAll(long targetPC) throws IOException {
		List<Integer> result = new ArrayList<Integer>();
		while (pc <= targetPC) {
			if (!step()) {
				return result;
			}
			result.add(value);
		}
		return result;
	}

	private boolean step() throws IOException {
		int uvdelta = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		if (uvdelta == 0 && pc != funcEntry) {
			// a delta of 0 is only valid on the first element
			return false;
		}
		value += -(uvdelta & 1) ^ (uvdelta >> 1);

		int pcdelta = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		pc += pcdelta * pcquantum;

		return true;
	}
}
