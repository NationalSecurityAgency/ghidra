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
package ghidra.app.plugin.core.analysis;

import ghidra.program.model.lang.*;

public class PicProcessor {

    /*Microchip*/
    public static final Processor PROCESSOR_PIC_12 = Processor.findOrPossiblyCreateProcessor("PIC-12");
    public static final Processor PROCESSOR_PIC_16 = Processor.findOrPossiblyCreateProcessor("PIC-16");
    public static final Processor PROCESSOR_PIC_17 = Processor.findOrPossiblyCreateProcessor("PIC-17");
    public static final Processor PROCESSOR_PIC_18 = Processor.findOrPossiblyCreateProcessor("PIC-18");

    private PicProcessor() {}
}
