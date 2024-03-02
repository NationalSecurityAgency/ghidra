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
package ghidra.pcodeCPort.slghpatexpress;

import java.io.IOException;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.utils.MutableInt;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

public abstract class PatternExpression {
	public final Location location;

	private int refcount; // Number of objects referencing this

	protected void dispose() {
	} // Only delete through release

	public PatternExpression(Location location) {
		this.location = location;
		refcount = 0;
	}

	public abstract TokenPattern genMinPattern(VectorSTL<TokenPattern> ops);

	public abstract void listValues(VectorSTL<PatternValue> list);

	public abstract void getMinMax(VectorSTL<Long> minlist, VectorSTL<Long> maxlist);

	public abstract long getSubValue(VectorSTL<Long> replace, MutableInt listpos);

	public abstract void encode(Encoder encoder) throws IOException;

	public long getSubValue(VectorSTL<Long> replace) {
		MutableInt listpos = new MutableInt(0);
		return getSubValue(replace, listpos);
	}

	public void layClaim() {
		refcount += 1;
	}

	public static void release(PatternExpression p) {
		p.refcount -= 1;
		if (p.refcount <= 0) {
			p.dispose();
		}
	}

}
