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
package ghidra.file.formats.android.dex;

import org.objectweb.asm.MethodVisitor;

import com.googlecode.d2j.Method;
import com.googlecode.d2j.dex.DexExceptionHandler;
import com.googlecode.d2j.node.DexMethodNode;

class DexToJarExceptionHandler implements DexExceptionHandler {
	private Exception e;

	@Override
	public void handleMethodTranslateException(Method method, DexMethodNode node,
			MethodVisitor visitor, Exception e) {
		this.e = e;
	}

	@Override
	public void handleFileException(Exception e) {
		this.e = e;
	}

	Exception getFileException() {
		return e;
	}

}
