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
 * Created on Feb 8, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.expression;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * Base class for binary operators that combine PatternExpressions
 */
public abstract class BinaryExpression extends PatternExpression {
	private PatternExpression left, right;

	@Override
	public int hashCode() {
		int result = 0;
		result += left.hashCode();
		result *= 31;
		result += this.getClass().hashCode();
		result *= 31;
		result += right.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (!this.getClass().equals(obj.getClass())) {
			return false;
		}
		BinaryExpression that = (BinaryExpression) obj;
		if (!this.left.equals(that.left)) {
			return false;
		}
		if (!this.right.equals(that.right)) {
			return false;
		}
		return true;
	}

	public BinaryExpression() {
	}

	public PatternExpression getLeft() {
		return left;
	}

	public PatternExpression getRight() {
		return right;
	}

	@Override
	public void decode(Decoder decoder, SleighLanguage lang) throws DecoderException {
		int el = decoder.openElement();
		left = PatternExpression.decodeExpression(decoder, lang);
		right = PatternExpression.decodeExpression(decoder, lang);
		decoder.closeElement(el);
	}
}
