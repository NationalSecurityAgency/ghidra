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
/**
 * The stand-alone Taint Emulator
 * 
 * <p>
 * This and the {@link ghidra.pcode.emu.taint} packages contain all the parts necessary to construct
 * a stand-alone emulator. Because this is a working solution, the state components already have
 * provisions in place for extension to support the fully-integrated solution. Generally, it's a bit
 * easier to just get the basic state components implemented, put tests in place, and then re-factor
 * them to permit extension as you address each more integrated emulator.
 * 
 * <p>
 * For this package, I recommend a top-down approach, since the top component provides a flat
 * catalog of the lower components. That top piece is actually in a separate package. See
 * {@link ghidra.pcode.emu.taint.TaintPartsFactory}. That factory is then used in
 * {@link TaintPcodeEmulator} to realize the stand-alone emulator. When you get to the state pieces,
 * you may want to pause and read {@link TaintSpace} first.
 */
package ghidra.pcode.emu.taint.plain;
