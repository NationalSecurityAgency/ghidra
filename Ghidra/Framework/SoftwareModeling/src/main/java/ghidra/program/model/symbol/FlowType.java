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
package ghidra.program.model.symbol;

/**
 * Class to define flow types for instruction (how it
 * flows from one instruction to the next)
 */
public final class FlowType extends RefType {
    
    private final boolean hasFall;
	private final boolean isCall;
	private final boolean isJump;
	private final boolean isTeminal;
	private final boolean isConditional;
	private final boolean isComputed;

	protected FlowType(byte type, String name, boolean hasFall, boolean isCall, boolean isJump, boolean isTeminal, boolean isComputed, boolean isConditional) {
    	super(type, name);
		this.hasFall = hasFall;
		this.isCall = isCall;
		this.isJump = isJump;
		this.isTeminal = isTeminal;
		this.isComputed = isComputed;
		this.isConditional = isConditional;
    }

	@Override
	public boolean hasFallthrough() {
		return hasFall;
	}

	@Override
	public boolean isCall() {
		return isCall;
	}

	@Override
	public boolean isComputed() {
		return isComputed;
	}

	@Override
	public boolean isConditional() {
		return isConditional;
	}

	@Override
	public boolean isFlow() {
		return true;
	}

	@Override
	public boolean isJump() {
		return isJump;
	}

	@Override
	public boolean isTerminal() {
		return isTeminal;
	}

	@Override
	public boolean isUnConditional() {
		return !isConditional;
	}

}
