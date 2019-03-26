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
import java.util.function.Function;

public class LdcTest{

    public LdcTest(){
    }
 
    int testReturnIntFromConstantPool(boolean flag){
        return 0x12345678;
    }

    float testReturnFloatFromConstantPool(boolean flag){
        return 0.123f;
    }

    String testReturnStringFromConstantPool(boolean flag){
        return "testString";
    }

    Class testReturnClassFromConstantPool(boolean flag){
        return String.class;
    }

    double testReturnDoubleFromConstantPool(){
        return 123.123;
    }

    long testReturnLongFromConstantPool(){
        return 0x123456789ABCDEFl;
    }

    static void methodHandleCaller(){
        methodHandleCallee(LdcTest::testHandle);
        return;
    }
    
    static void methodHandleCallee(Function<String,Integer> func){
        return;
    }

    static Integer testHandle(String s){
        return s.length();
    } 
        
    //references to method types or handles - need reflection for this?
}


