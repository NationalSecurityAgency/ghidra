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
package ghidra.async;

import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.BooleanConfigFieldCodec;
import ghidra.framework.plugintool.AutoConfigState.ConfigFieldCodec;

public interface AsyncConfigFieldCodec {
	static class GenericAsyncConfigFieldCodec<T>
			implements ConfigFieldCodec<AsyncReference<T, ?>> {
		private ConfigFieldCodec<T> codec;

		public GenericAsyncConfigFieldCodec(ConfigFieldCodec<T> codec) {
			this.codec = codec;
		}

		@Override
		public AsyncReference<T, ?> read(SaveState state, String name,
				AsyncReference<T, ?> current) {
			current.set(codec.read(state, name, current.get()), null);
			return current;
		}

		@Override
		public void write(SaveState state, String name, AsyncReference<T, ?> value) {
			codec.write(state, name, value.get());
		}
	}

	static class BooleanAsyncConfigFieldCodec
			extends GenericAsyncConfigFieldCodec<Boolean> {
		public BooleanAsyncConfigFieldCodec() {
			super(BooleanConfigFieldCodec.INSTANCE);
		}
	}

	// TODO: Other types as needed
}
