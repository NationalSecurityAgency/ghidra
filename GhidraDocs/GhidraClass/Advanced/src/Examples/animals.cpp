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
#include<string>
#include<iostream>

class Animal{
    protected:
        unsigned long weight;
        unsigned long age;
        std::string name;
    public:
        Animal(long w, long a, std::string n){
            weight = w;
            age = a;
            name = n;
        }
        void printInfo(){
            std::cout << "Name: " << name << ", age: " << age << ", weight: " << weight << '\n';     
        } 
        std::string getName(void){ return name;}
        virtual void printSound(void) = 0; 
        virtual void printSpecificFact(void) = 0;
        virtual int getAnimalAge(void) = 0;
};

class Cat : public Animal {
    protected:
        unsigned long numLives;
    public:
        Cat(unsigned long w, unsigned long a, std::string n, long num) : Animal(w,a,n){
            numLives = num;
        }
        void printSound(void) { std::cout << name << " says MEOW!\n";}
        void printSpecificFact(void){ std::cout << name + " has " + std::to_string(numLives) + " lives";}
        int getAnimalAge(void){ return age * 4 + 20;}
};

class Dog : public Animal {
    protected:
        bool wantsWalk;
    public:
        Dog(unsigned long w, unsigned long a, std::string n): Animal(w,a,n){
            wantsWalk = true;
        }
        void printSound(void) {std::cout << name << " says BARK!\n";}
        void printSpecificFact(void) {std::cout << name + " wants a walk";}
        int getAnimalAge(void) {return age * 7;}
};



int main(int argc, char **argv){
    Animal *a;
    if (argc % 2 == 0){
        a = new Cat(8,3,"Lord Meowington II",9);
    }
    else {
        a = new Dog(60, 5, "Pigblob 9000");
    }
    std::cout << '\n';
    a->printInfo();
    a->printSound();
    a->printSpecificFact(); 
    int animalAge = a->getAnimalAge();
    delete(a);
    return animalAge;
}





