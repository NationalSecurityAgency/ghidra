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
package ghidra.pcodeCPort.slghsymbol;

import ghidra.pcodeCPort.context.ParserWalkerChange;
import ghidra.pcodeCPort.sleighbase.SleighBase;

import java.io.PrintStream;

import org.jdom.Element;

// Change to context command
public abstract class ContextChange {

	public ContextChange() {
	}

	public abstract void validate();

	public abstract void saveXml(PrintStream s);

	public abstract void restoreXml(Element el, SleighBase trans);

	public abstract void apply(ParserWalkerChange pos);

	public void dispose() {
	}
}
