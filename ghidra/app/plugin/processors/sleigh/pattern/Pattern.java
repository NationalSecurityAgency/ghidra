/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.processors.sleigh.pattern;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.program.model.mem.*;
import ghidra.xml.*;

/**
 * 
 *
 * A pattern which either matches or doesnt match a particular
 * InstructionContext.  In particular, the bits comprising the
 * current instruction in the executable, and possible other
 * context bits
 */
public abstract class Pattern {
	public abstract Pattern simplifyClone();
	public abstract void shiftInstruction(int sa);
	public abstract Pattern doOr(Pattern b,int sa);
	public abstract Pattern doAnd(Pattern b,int sa);
	public abstract boolean isMatch(ParserWalker walker, SleighDebugLogger debug) throws MemoryAccessException;
	public abstract int numDisjoint();
	public abstract DisjointPattern getDisjoint(int i);
	public abstract boolean alwaysTrue();
	public abstract boolean alwaysFalse();
	public abstract boolean alwaysInstructionTrue();
	public abstract void restoreXml(XmlPullParser parser);
}
