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
 * This package cannot share the same name as the package in main, because that package contains all
 * the scaffolding. Otherwise, when it is exported by
 * {@link ghidra.comm.util.pyexport.GeneratePython}, it gets confused, since it tries to export that
 * scaffolding, and thinks classes referred to in it are getting exported. That should never be the
 * case. Each target language for export must provide its own scaffolding.
 */
package ghidra.comm.tests.packet;
