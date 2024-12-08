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
 * List of function ids for runtime._func (GoFuncData) funcID field.
 */
public enum GoFuncID {
	NORMAL,
	ABORT,
	ASMCGOCALL,
	ASYNCPREEMPT,
	CGOCALLBACK,
	DEBUGCALLV2,
	GCBGMARKWORKER,
	GOEXIT,
	GOGO,
	GOPANIC,
	HANDLEASYNCEVENT,
	MCALL,
	MORESTACK,
	MSTART,
	PANICWRAP,
	RT0_GO,
	RUNFINQ,
	RUNTIME_MAIN,
	SIGPANIC,
	SYSTEMSTACK,
	SYSTEMSTACK_SWITCH,
	WRAPPER;

	public static GoFuncID parseIDByte(int b) {
		GoFuncID[] values = values();
		return 0 <= b && b < values.length ? values[b] : null;
	}
}
