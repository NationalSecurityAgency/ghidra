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

import java.nio.ByteBuffer;

import com.sun.jna.platform.win32.WinDef.ULONGLONGByReference;

import agent.dbgmodel.dbgmodel.UnknownEx;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;

/**
 * A wrapper for {@code IDebugHostMemory1} and its newer variants.
 */
public interface DebugHostMemory1 extends UnknownEx {

	long readBytes(DebugHostContext context, LOCATION location, ByteBuffer buffer, long bufferSize);

	long writeBytes(DebugHostContext context, LOCATION location, ByteBuffer buffer,
			long bufferSize);

	ULONGLONGByReference readPointers(DebugHostContext context, LOCATION location, long count);

	ULONGLONGByReference writePointers(DebugHostContext context, LOCATION location, long count);

	String GetDisplayStringForLocation(DebugHostContext context, LOCATION location,
			boolean verbose);

}
