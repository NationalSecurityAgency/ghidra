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
package ghidra.pyghidra.test;

import ghidra.app.util.recognizer.Recognizer;

/**
 * Simple ExtensionPoint class for PyGhidra plugin test.
 * 
 * This can be any ExtensionPoint. Recognizer was chosen here
 * because it has a small number of methods and hasn't changed in a long time.
 */
public class DummyTestRecognizer implements Recognizer {
    
    // simple static field we can reach and check for a pytest
    // normally this would be an interface implemented in Python
    // that would be set so this class can call into Python
    public static boolean preLaunchInitialized = false;
    
    @Override
    public int getPriority() {
        return 0;
    }
    
    @Override
    public int numberOfBytesRequired() {
        return 0;
    }
    
    @Override
    public String recognize(byte[] bytes) {
        return "";
    }
}
