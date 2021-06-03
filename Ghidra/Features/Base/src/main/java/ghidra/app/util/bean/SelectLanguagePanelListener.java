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
/*
 * Created on Aug 8, 2006
 */
package ghidra.app.util.bean;

import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;

/**
 * A listener for the SelectLanguagePanel
 */
public interface SelectLanguagePanelListener {
    /**
     * This method is invoked every time a languauge is selected.
     * NOTE: the language could be null.
     * @param langID the selected language id.
     * @param compilerSpecID the selected compiler spec id.
     */
    public void selectIDValidation(LanguageID langID, CompilerSpecID compilerSpecID);
}
