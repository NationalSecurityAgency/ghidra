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
package ghidra.app.plugin.core.debug.gui.breakpoint;

import java.util.List;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.DecompileProcess.DisposeState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class MockDecompileResults extends DecompileResults {
	private ClangTokenGroup root;

	public interface ClangBuilder<T extends ClangNode> {
		T build(ClangTokenGroup parent);

		default T build() {
			return build(null);
		}
	}

	public static class MockToken extends ClangToken {
		private final Address address;

		public MockToken(ClangNode parent, String txt, Address address) {
			super(parent, txt);
			this.address = address;
		}

		public MockToken(ClangNode parent, String txt) {
			this(parent, txt, null);
		}

		@Override
		public Address getMinAddress() {
			return address;
		}

		@Override
		public Address getMaxAddress() {
			return address;
		}
	}

	public static class TokenBuilder implements ClangBuilder<ClangToken> {
		private final String text;
		private final Address address;

		public TokenBuilder(String text, Address address) {
			this.text = text;
			this.address = address;
		}

		public TokenBuilder(String text) {
			this(text, null);
		}

		@Override
		public ClangToken build(ClangTokenGroup parent) {
			return new MockToken(parent, text, address);
		}
	}

	public static class GroupBuilder implements ClangBuilder<ClangTokenGroup> {
		private final List<ClangBuilder<?>> children;

		public GroupBuilder(ClangBuilder<?>... children) {
			this.children = List.of(children);
		}

		protected ClangTokenGroup newGroup(ClangTokenGroup parent) {
			return new ClangTokenGroup(parent);
		}

		@Override
		public ClangTokenGroup build(ClangTokenGroup parent) {
			ClangTokenGroup group = newGroup(parent);
			for (ClangBuilder<?> child : children) {
				group.AddTokenGroup(child.build(group));
			}
			return group;
		}
	}

	public MockDecompileResults(Function function) {
		super(function, function.getProgram().getLanguage(),
			function.getProgram().getCompilerSpec(), null, "", null, DisposeState.NOT_DISPOSED);
	}

	@Override
	public ClangTokenGroup getCCodeMarkup() {
		return root;
	}

	protected void root(GroupBuilder group) {
		root = group.build();
	}

	protected GroupBuilder function(ClangBuilder<?>... children) {
		return new GroupBuilder(children) {
			@Override
			protected ClangTokenGroup newGroup(ClangTokenGroup parent) {
				return new ClangFunction(parent, null);
			}
		};
	}

	protected GroupBuilder group(ClangBuilder<?>... children) {
		return new GroupBuilder(children);
	}

	protected TokenBuilder token(String text) {
		return new TokenBuilder(text);
	}

	protected TokenBuilder token(String text, Address address) {
		return new TokenBuilder(text, address);
	}
}
