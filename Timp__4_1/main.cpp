#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/md5.h>
using namespace std;
int main(int argc, char **argv)
{

    CryptoPP::MD5 hash;//создаем хэш-объект MD5
    std::string msg = "";//строка от которой вычисляем хэш
    std::string path="/home/student/hash";
    fstream fs;
    fs.open(path,fstream::in);//открываем файл с возможностью чтения
    if (!fs.is_open()) {//проверка
        cout<<"Ошибка открытия файла!"<<endl;
        exit(0);
    }
    getline(fs,msg);//данные из файла помещаем в строку
    std::vector<byte> digest(hash.DigestSize());//вектор из байтов - для хэша, размер = размеру хэша
    

    hash.Update((const byte*)msg.data(),msg.size());//считаем хэш, передаем указатель на наши данные и размер наших данных
    hash.Final(digest.data());//помещаем результат в вектор

    cout<<"Message: "<<msg<<endl;
    cout<<"Digest: ";

    CryptoPP::StringSource(digest.data(),digest.size(),true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(cout)));//объект ввода из строки,передаем вектор, выводим в фильтр, выводим в cout
    cout<<endl;
    return 0;
}
