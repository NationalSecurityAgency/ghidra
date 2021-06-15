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
package agent.dbgmodel.dbgmodel.debughost;

import agent.dbgmodel.jna.dbgmodel.DbgModelNative.*;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.ARRAY_DIMENSION.ByReference;

/**
 * A wrapper for {@code IDebugHostType1} and its newer variants.
 */
public interface DebugHostType1 extends DebugHostBase {

	TypeKind getTypeKind();

	long getSize();

	DebugHostType1 getBaseType();

	int getHashCode();

	IntrinsicKind getIntrinsicType();

	void getBitField();

	PointerKind getPointerKind();

	DebugHostType1 getMemberType();

	DebugHostType1 createPointerTo(int kind);

	long getArrayDimensionality();

	ARRAY_DIMENSION getArrayDimensions(long dimensions);

	DebugHostType1 createArrayOf(long dimensions, ByReference pDimensions);

	int getFunctionCallingConvention();

	DebugHostType1 getFunctionReturnType();

	DebugHostType1 getFunctionParameterTypeAt(int i);

	boolean isGeneric();

	long getGenericArgumentCount();

	DebugHostSymbol1 getGenericArgumentAt(int i);
}
