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
package ghidra.feature.vt.gui.wizard;

enum VTWizardStateKey {
	WIZARD_OP_DESCRIPTION, EXISTING_SESSION, SESSION_NAME,

	SOURCE_PROGRAM_FILE, DESTINATION_PROGRAM_FILE,

	SOURCE_PROGRAM, DESTINATION_PROGRAM,

	SOURCE_ADDRESS_SET_VIEW, DESTINATION_ADDRESS_SET_VIEW,

	PRECONDITION_CHECKS_RUN,

	NEW_SESSION_FOLDER,

	ADDRESS_RANGES_MODE,

	PROGRAM_CORRELATOR_FACTORY_LIST,

	PROGRAM_CORRELATOR_OPTIONS_LIST, HIGHEST_PRECONDITION_STATUS,

	SHOW_ADDRESS_SET_PANELS,

	EXCLUDE_ACCEPTED_MATCHES,

	SOURCE_SELECTION, DESTINATION_SELECTION,

	SOURCE_ADDRESS_SET_CHOICE, DESTINATION_ADDRESS_SET_CHOICE;
}
