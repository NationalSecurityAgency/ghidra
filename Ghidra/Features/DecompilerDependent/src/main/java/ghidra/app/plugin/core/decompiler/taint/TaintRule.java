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
package ghidra.app.plugin.core.decompiler.taint;

public enum TaintRule {

	UNKNOWN("UNKNOWN"),
	SOURCE("Source"),
	SINK("Sink"),
	GATE("Gate"),
	INSN("Instruction"),
	VERTEX("Vertex"),
	PATH("Path");

	private String name;

	private TaintRule(String name) {
		this.name = name;
	}

	public static TaintRule fromRuleId(String ruleId) {
		if (ruleId.contains("C0003")) {
			return SOURCE;
		}
		else if (ruleId.contains("C0001")) {
			return PATH;
		}
		else if (ruleId.contains("C0004")) {
			return SINK;
		}
		else if (ruleId.contains("C0002")) {
			return INSN;
		}
		else if (ruleId.contains("C0005")) {
			return VERTEX;
		}
		else {
			return UNKNOWN;
		}
	}

	@Override
	public String toString() {
		return this.name;
	}

}
