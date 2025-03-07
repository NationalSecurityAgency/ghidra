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
package ghidra.app.util.bin.format.golang.rtti.types;

import java.io.IOException;

import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
import ghidra.app.util.bin.format.golang.rtti.GoTypeManager;
import ghidra.program.model.data.DataType;

/**
 * A limited use wrapper/bridge between a GoType and a Ghidra DataType, this
 * wrapper only supports the {@link #recoverDataType(GoTypeManager)} call.
 */
public class GoTypeBridge extends GoType {

	private DataType ghidraType;
	private final GoType delegateGoType;
	private final String delegateTypeName;

	public GoTypeBridge(GoType delegateGoType, DataType ghidraType, GoRttiMapper goBinary) {
		this.ghidraType = ghidraType;
		this.delegateGoType = delegateGoType;
		this.delegateTypeName = delegateGoType.getName();
		this.programContext = goBinary;
	}
	
	public GoTypeBridge(String delegateGoTypeName, DataType ghidraType, GoRttiMapper goBinary) {
		this.ghidraType = ghidraType;
		this.delegateGoType = null;
		this.delegateTypeName = delegateGoTypeName;
		this.programContext = goBinary;
	}

	@Override
	public DataType recoverDataType(GoTypeManager goTypes) throws IOException {
		if (ghidraType == null) {
			ghidraType = goTypes.getGhidraDataType(delegateGoType);
		}
		return ghidraType;
	}
	
	@Override
	public String getPackagePathString() {
		return delegateGoType != null ? delegateGoType.getPackagePathString() : "";
	}

	@Override
	public String getName() {
		return delegateTypeName;
	}

	@Override
	public String toString() {
		return "GoTypeBridge [ghidraType=" + ghidraType + ", delegateGoType=" + delegateGoType + "]";
	}

}
