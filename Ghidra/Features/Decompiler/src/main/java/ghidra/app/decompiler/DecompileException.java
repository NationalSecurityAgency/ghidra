/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
/*
 * Created on Jun 3, 2005
 *
 */
package ghidra.app.decompiler;

/**
 * An exception from (or that has passed through) the decompiler process
 * 
 * 
 */
public class DecompileException extends Exception {
	private static final long serialVersionUID = 1L;

	public DecompileException(String type,String msg) {
		super(type + ": "+msg);
	}
	
	@Override
	public String toString() {
	    return "DecompileException: " + getMessage();
	}
}
