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
package ghidra.app.plugin.processors.sleigh.symbol;

import ghidra.app.plugin.processors.sleigh.expression.PatternValue;

/**
 * 
 *
 * TripleSymbols whose semantic value and printing changes depending
 * on the pattern that they match
 */
public abstract class FamilySymbol extends TripleSymbol {
	public abstract PatternValue getPatternValue();
}
