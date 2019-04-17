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
 * Window - Preferences - Java - Code Style - Code Templates
 */
package ghidra.app.plugin.processors.sleigh.expression;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * Base class for unary operators on PatternExpressions
 */

public abstract class UnaryExpression extends PatternExpression {
	private PatternExpression unary;

	@Override
	public int hashCode() {
		int result = 0;
		result += this.getClass().hashCode();
		result *= 31;
		result += unary.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (!this.getClass().equals(obj.getClass())) {
			return false;
		}
		UnaryExpression that = (UnaryExpression) obj;
		if (!this.unary.equals(that.unary)) {
			return false;
		}
		return true;
	}

	public PatternExpression getUnary() {
		return unary;
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage lang) {
		XmlElement el = parser.start();

		unary = PatternExpression.restoreExpression(parser, lang);
		parser.end(el);
	}
}
