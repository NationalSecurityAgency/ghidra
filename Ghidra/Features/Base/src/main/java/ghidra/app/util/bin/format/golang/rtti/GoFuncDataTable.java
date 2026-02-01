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
package ghidra.app.util.bin.format.golang.rtti;

/**
 * An index into a GoFuncData's variable-size funcdata array.  See GoFuncData's nfuncdata for
 * actual array size.
 */
public enum GoFuncDataTable {
	FUNCDATA_ArgsPointerMaps, // 0
	FUNCDATA_LocalsPointerMaps, // 1
	FUNCDATA_StackObjects, // 2;
	FUNCDATA_InlTree, // 3
	FUNCDATA_OpenCodedDeferInfo, // 4
	FUNCDATA_ArgInfo, // 5
	FUNCDATA_ArgLiveInfo, // 6
	FUNCDATA_WrapInfo // 7
}
