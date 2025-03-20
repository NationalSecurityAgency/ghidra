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
package ghidra.app.plugin.core.analysis.rust;

import ghidra.program.model.data.CategoryPath;

public class RustConstants {
	public static final CategoryPath RUST_CATEGORYPATH = new CategoryPath("/rust");
	public static final byte[] RUST_SIGNATURE_1 = "RUST_BACKTRACE".getBytes();
	public static final byte[] RUST_SIGNATURE_2 = "/rustc/".getBytes();
	public static final byte[] RUST_SIGNATURE_3 = "RUST_MIN_STACK".getBytes();
	public static final String RUST_EXTENSIONS_PATH = "extensions/rust/";
	public static final String RUST_EXTENSIONS_UNIX = "unix";
	public static final String RUST_EXTENSIONS_WINDOWS = "windows";
	public static final String RUST_COMPILER = "rustc";
}
