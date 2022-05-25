#include <iostream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <string>
using namespace std;
string encrypt2(string plain_text, byte* iv, CryptoPP::SecByteBlock key);//ф. шифрования DES
void decrypt2(string cipher_text, byte* iv,CryptoPP::SecByteBlock key);//ф. расшифрования DES
string file_in_string(string path);//ф. перемещения текста из файла в строку
string encrypt(string plain_text, byte* iv,CryptoPP::SecByteBlock key);//ф. шифрования AES
void decrypt(string cipher_text, byte* iv,CryptoPP::SecByteBlock key);//ф. расшифрования AES
int main(int argc, char **argv)
{
    //key from password
    std::string psw2="SuperPa$$w0rd";//пароль
    std::string salt2="Соль земли русской";//спец случ значение соль
    CryptoPP::SecByteBlock key2(CryptoPP::DES::DEFAULT_KEYLENGTH);//создаем спец объект SecByteBlock  
    CryptoPP::PKCS12_PBKDF<CryptoPP::SHA1> pbkdf2;//создаем спец объект для форм-ия ключа из пароля PKCS12_PBKDF это шаблон, указываем алгоритм SHA1 для формирования ключа
    pbkdf2.DeriveKey(key2.data(),key2.size(),0,(byte*)psw2.data(),psw2.size(),(byte*)salt2.data(),salt2.size(),1024,0.0f);//формируем ключ, передаем ключ и его размер, 0, пароль, размер, соль, размер соли, количество итераций выполнения функций, время
    cout<<"Key: ";
    CryptoPP::StringSource(key2.data(),key2.size(),true,new CryptoPP::HexEncoder(new CryptoPP::FileSink(cout)));//выводим ключ
    cout<<endl;

    //random IV
    CryptoPP::AutoSeededRandomPool prng2;//генерируем случайное число
    byte iv2[CryptoPP::DES::BLOCKSIZE];//массив байт вектора инизиализации размер вектора размеру блока алгоритма
    prng2.GenerateBlock(iv2,sizeof(iv2));//генерируем блок данных по размеру вектора iv
    cout<<"IV: ";
    CryptoPP::StringSource(iv2,sizeof(iv2),true,new CryptoPP::HexEncoder(new CryptoPP::FileSink(cout)));//выводим вектор iv
    cout<<endl;
    
    //key from password
    std::string psw="SuperPa$$w0rd";//пароль
    std::string salt="Соль - добрая вещь; но ежели соль не солона будет, чем вы ее поправите?";
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::PKCS12_PBKDF<CryptoPP::SHA1> pbkdf;
    pbkdf.DeriveKey(key.data(),key.size(),0,(byte*)psw.data(),psw.size(),(byte*)salt.data(),salt.size(),1024,0.0f);
    cout<<"Key: ";//
    CryptoPP::StringSource(key.data(),key.size(),true,new CryptoPP::HexEncoder(new CryptoPP::FileSink(cout)));
    cout<<endl;

    //random IV
    CryptoPP::AutoSeededRandomPool prng;
    byte iv[CryptoPP::AES::BLOCKSIZE];//объявляем массив байт вектора инизиализации
    prng.GenerateBlock(iv,sizeof(iv));//генерируем блок данных по размеру вектора ин
    cout<<"IV: ";
    CryptoPP::StringSource(iv,sizeof(iv),true,new CryptoPP::HexEncoder(new CryptoPP::FileSink(cout)));//выводим вектор ин
    cout<<endl;
    
    string path;
    cout<<"Введите название файла:";
    cin>>path;
    std::string plain_text=file_in_string(path);//i
    std::string cipher_text, encoded_text, recovered_text;
    cout<<"plain_text: "<< plain_text<<endl;
    
        unsigned op;
    do {
        cout<<"Input operation (0-exit, 1-AES, 2-DES): ";
        cin>>op;
        if (op > 2) {
            cout<<"Illegal operation\n";
        } else if (op >0) {
            if (op==1) {
                unsigned op1;
                do {
                    cout<<"Input operation (0-exit, 1-encrypt_AES, 2-decrypt_AES): ";
                    cin>>op1;
                    if (op1 > 2) {
                        cout<<"Illegal operation\n";
                    } else if (op >0) {
                        if (op1==1) {
                            cipher_text=encrypt(plain_text,iv,key);
                        } else {
                            decrypt(cipher_text,iv,key);
                        }
                    }
                } while (op1!=0);
            } else {
                unsigned op2;
                do {
                    cout<<"Input operation (0-exit, 1-encrypt_DES, 2-decrypt_DES): ";
                    cin>>op2;
                    if (op2 > 2) {
                        cout<<"Illegal operation\n";
                    } else if (op2 >0) {
                        if (op2==1) {
                            cipher_text=encrypt2(plain_text,iv2,key2);
                        } else {
                            decrypt2(cipher_text,iv2,key2);
                        }
                    }
                } while (op2!=0);
            }
        }
    } while (op!=0);

   return 0;
}

string file_in_string(string path)
{
    std::string msg = "";//строка от которой вычисляем хэш
    fstream fs;
    fs.open(path,fstream::in);//открываем файл с возможностью чтения
    if (!fs.is_open()) {//проверка
        cout<<"Ошибка открытия файла!"<<endl;
        exit(0);
    }
    getline(fs,msg);//данные из файла помещаем в строку
    return msg;
}
string encrypt(string plain_text, byte* iv,CryptoPP::SecByteBlock key)
{
    string cipher_text,encoded_text;
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encr;// создаем объект Encryption 
        encr.SetKeyWithIV(key,key.size(),iv);//устанавливаем ключ 
        
        //сам процесс шифрования
        CryptoPP::StringSource ss(plain_text,true, new CryptoPP::StreamTransformationFilter(encr, new CryptoPP::StringSink(cipher_text)));

    } catch (const CryptoPP::Exception& e) {//ловит исключения CryptoPP::Exception
        std::cerr<<e.what()<<std::endl;//
        exit(1);//
    }
    // print result
    CryptoPP::StringSource ss(cipher_text,true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded_text)));//выводим результатs v encoded в 16 ричном виде
    cout<<"cipher text: " <<encoded_text<<endl;//выводим зашифрованную строку
    return cipher_text;
}
void decrypt(string cipher_text, byte* iv,CryptoPP::SecByteBlock key)
{
    string recovered_text;
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decr; //создаем объект 
        decr.SetKeyWithIV(key,key.size(), iv);//устанавливаем ключ
        
        //расшифровываем
        CryptoPP::StringSource ss(cipher_text,true,new CryptoPP::StreamTransformationFilter(decr,new CryptoPP::StringSink(recovered_text)));//выводим расшифрованную строку в рековеред_текст


    } catch (const CryptoPP::Exception& e) {//ловим исключения CryptoPP::Exception
        std::cerr<<e.what()<<endl;
        exit(1);
    }
    //print result
    cout<<"recovered text: "<<recovered_text<<endl;//выводим расшифрованную строку
}
string encrypt2(string plain_text, byte* iv, CryptoPP::SecByteBlock key){
    string cipher_text,encoded_text;
    try {
        CryptoPP::CBC_Mode<CryptoPP::DES>::Encryption encr;// создаем объект энкр
        encr.SetKeyWithIV(key,key.size(),iv);//устанавливаем ключ потом сам процесс шифрования

        CryptoPP::StringSource ss(plain_text,true, new CryptoPP::StreamTransformationFilter(encr, new CryptoPP::StringSink(cipher_text)));//источник стринг сурс - фильтруем строку ,
        //стреам трансформайшон фильтр вх-е энкр выводим в строку чипер текст


    } catch (const CryptoPP::Exception& e) {//ищем исключения криптопп эксепшен
        std::cerr<<e.what()<<std::endl;//
        exit(1);//
    }
    // print result
    CryptoPP::StringSource ss(cipher_text,true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded_text)));//выводим результатs v encoded в 16 ричном виде
    cout<<"cipher text: " <<encoded_text<<endl;//выводим зашифрованную строку
    return cipher_text;
}
void decrypt2(string cipher_text, byte* iv,CryptoPP::SecByteBlock key){
    //decrypt расшифровываем
    string recovered_text;
    try {
        CryptoPP::CBC_Mode<CryptoPP::DES>::Decryption decr;//
        decr.SetKeyWithIV(key,key.size(), iv);//

        CryptoPP::StringSource ss(cipher_text,true,new CryptoPP::StreamTransformationFilter(decr,new CryptoPP::StringSink(recovered_text)));
        //строка зашифрованая подается и выводится расшифрованная в строку рековеред

    } catch (const CryptoPP::Exception& e) {//
        std::cerr<<e.what()<<endl;//
        exit(1);//
    }
    //print result
    cout<<"recovered text: "<<recovered_text<<endl;//выводим расшифрованную строку
}