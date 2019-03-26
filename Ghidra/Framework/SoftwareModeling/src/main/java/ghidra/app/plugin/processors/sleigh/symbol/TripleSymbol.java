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
/*
 * Created on Feb 7, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.symbol;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * 
 *
 * Abstract class for the primary sleigh variable. An object that
 * has a printing, pattern, and semantic interpretation
 */
public abstract class TripleSymbol extends Symbol {

	public abstract PatternExpression getPatternExpression();

	public Constructor resolve(ParserWalker walker, SleighDebugLogger debug)
			throws MemoryAccessException, UnknownInstructionException {
		return null;
	}
	public abstract void getFixedHandle(FixedHandle hand, ParserWalker walker) throws MemoryAccessException;
	public abstract String print(ParserWalker walker) throws MemoryAccessException;
	public abstract void printList(ParserWalker walker, ArrayList<Object> list) throws MemoryAccessException;
}
