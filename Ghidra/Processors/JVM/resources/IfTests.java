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
class IfTests{

    public int testBoolean(boolean x){
        if (x){
            return 1;
        }
        return 0;
    }

    public int testByte(byte x){
        if (x == 0){
            return 1;
        }
        return 0;
   }

   public int testChar(char x){
       if (x == 0){
           return 1;
       }
       return 0;
   }

   public int testShort(short x){
       if (x == 0){
           return 1;
       }
       return 0;
   }

   public void loop(boolean x){
       while(x);
   }

   public void infiniteLoop(){
       while(true); 
   }

   public short addShorts(short a, short b){
       return (short) (a+b);
   }

   public int addShorts2(short a, short b){
       return a+b;
   }

   public boolean isEven(int x){
       return (x%2)==0;
   }

   public int callsIsEven(int x){
       if(isEven(x)){
           return 0;
       }
       else {
           return 1;
       }
   }
} 




