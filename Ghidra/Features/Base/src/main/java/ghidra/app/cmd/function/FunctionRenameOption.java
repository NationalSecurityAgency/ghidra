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
package ghidra.app.cmd.function;

import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;

/**
 * Option for controlling the renaming of a {@link Function} when applying a 
 * {@link FunctionSignature} or {@link FunctionDefinition}.
 * 
 * See {@link ApplyFunctionSignatureCmd}.
 */
public enum FunctionRenameOption {
	/**
	 * {@link #NO_CHANGE} indicates that the current {@link Function} name should be changed.
	 */
	NO_CHANGE,

	/**
	 * {@link #RENAME_IF_DEFAULT} indicates that the current {@link Function} name should be only
	 * be changed if it is a default name (e.g., FUN_1234).
	 */
	RENAME_IF_DEFAULT,

	/**
	 * {@link #RENAME} indicates that the current {@link Function} name should always be changed.
	 */
	RENAME;
}
