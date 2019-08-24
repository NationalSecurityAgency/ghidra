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
package ghidra.program.model.symbol;

/**
 * Class to define flow types for instruction (how it
 * flows from one instruction to the next)
 */
public final class FlowType extends RefType {

	private final boolean hasFall;
	private final boolean isCall;
	private final boolean isJump;
	private final boolean isTerminal;
	private final boolean isConditional;
	private final boolean isComputed;
	private final boolean isOverride;

	protected static class Builder {
		private byte type;
		private String name;

		private boolean hasFall = false;
		private boolean isCall = false;
		private boolean isJump = false;
		private boolean isTerminal = false;
		private boolean isComputed = false;
		private boolean isConditional = false;
		private boolean isOverride = false;

		protected Builder(byte type, String name) {
			this.type = type;
			this.name = name;
		}

		protected Builder setHasFall() {
			this.hasFall = true;
			return this;
		}

		protected Builder setIsCall() {
			this.isCall = true;
			return this;
		}

		protected Builder setIsJump() {
			this.isJump = true;
			return this;
		}

		protected Builder setIsTerminal() {
			this.isTerminal = true;
			return this;
		}

		protected Builder setIsComputed() {
			this.isComputed = true;
			return this;
		}

		protected Builder setIsConditional() {
			this.isConditional = true;
			return this;
		}

		protected Builder setIsOverride() {
			this.isOverride = true;
			return this;
		}

		protected FlowType build() {
			return new FlowType(this);
		}
	}

	private FlowType(Builder builder) {
		super(builder.type, builder.name);
		this.hasFall = builder.hasFall;
		this.isCall = builder.isCall;
		this.isJump = builder.isJump;
		this.isTerminal = builder.isTerminal;
		this.isComputed = builder.isComputed;
		this.isConditional = builder.isConditional;
		this.isOverride = builder.isOverride;
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
		return isTerminal;
	}

	@Override
	public boolean isUnConditional() {
		return !isConditional;
	}

	@Override
	public boolean isOverride() {
		return isOverride;
	}

}
