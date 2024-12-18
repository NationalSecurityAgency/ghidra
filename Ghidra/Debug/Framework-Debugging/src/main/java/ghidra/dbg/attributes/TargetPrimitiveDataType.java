/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.dbg.attributes;

import com.google.gson.JsonObject;

@Deprecated(forRemoval = true, since = "11.2")
public interface TargetPrimitiveDataType extends TargetDataType {
	public static final TargetDataType VOID =
		new DefaultTargetPrimitiveDataType(PrimitiveKind.VOID, 0);

	enum PrimitiveKind {
		UNDEFINED,
		VOID,
		UINT,
		SINT,
		FLOAT,
		COMPLEX;
	}

	public class DefaultTargetPrimitiveDataType implements TargetPrimitiveDataType {
		protected final PrimitiveKind kind;
		protected final int length;

		public DefaultTargetPrimitiveDataType(PrimitiveKind kind, int length) {
			this.kind = kind;
			this.length = length;
		}

		@Override
		public PrimitiveKind getKind() {
			return kind;
		}

		@Override
		public int getLength() {
			return length;
		}

		@Override
		public JsonObject toJson() {
			JsonObject object = new JsonObject();
			object.addProperty("kind", kind.toString());
			object.addProperty("length", length);
			return object;
		}
	}

	PrimitiveKind getKind();

	int getLength();
}
