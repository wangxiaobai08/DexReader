#pragma once
#include <stdint.h>
#include <cstdio>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <string>
using namespace std;
//byte	8 λ�з�������
//ubyte	8 λ�޷�������
//short	16 λ�з�������������С���ֽ���
//ushort	16 λ�޷�������������С���ֽ���
//int	32 λ�з�������������С���ֽ���
//uint	32 λ�޷�������������С���ֽ���
//long	64 λ�з�������������С���ֽ���
//ulong	64 λ�޷�������������С���ֽ���
//sleb128	�з��� LEB128���ɱ䳤��
//uleb128	�޷��� LEB128���ɱ䳤��
//uleb128p1	�޷��� LEB128 �� 1���ɱ䳤��

#define kSHA1DigestLen 20  // SHA-1 ��ϣֵ������ 20 �ֽ�

//byte
typedef int8_t s1;
typedef uint8_t u1;
//short
typedef int16_t s2;
typedef uint16_t u2;
//int
typedef int32_t s4;
typedef uint32_t u4;
//long
typedef int64_t s8;
typedef uint64_t u8;
//leb,���ڿɱ䳤�ȣ�����ʹ�ö�̬����洢 uleb128 ������ֽ�

 //---------�ļ�ͷ-------------------
struct DexHeader {
    u1  magic[8];           //��ʶ DEX �ļ������� DEX_FILE_MAGIC ="dex\n035\0"
    u4  checksum;          //�� magic �ʹ��ֶ�֮����ļ�ʣ�����ݵ� adler32 У��ͣ����ڼ���ļ������
    u1  signature[kSHA1DigestLen]; //�� magic��checksum �ʹ��ֶ�֮����ļ������ݵ� SHA-1 ǩ������ϣ�������ڶ��ļ�����Ψһ��ʶ
    u4  fileSize;           //�����ļ��������ļ�ͷ���Ĵ�С�����ֽ�Ϊ��λ
    u4  headerSize;         //�ļ�ͷ�Ĵ�С�����ֽ�Ϊ��λ��
    u4  endianTag;          //�ֽ����ǣ���������С����
    u4  linkSize;           //������ļ�δ���о�̬���ӣ����ֵΪ 0����֮Ϊ�������εĴ�С��
    u4  linkOff;            //��� link_size == 0�����ֵΪ 0�� ��֮����ƫ�������ļ���ͷ���� link_data ���ε�ƫ������
    u4  mapOff;             //��ƫ����������㣬��ʶ���ļ���ͷ�� data ���ε�ƫ������
    u4  stringIdsSize;      //�ַ�����ʶ���б��е��ַ�������
    u4  stringIdsOff;       //��� string_ids_size == 0�����ɷ�����һ����ֵļ�������������ֵΪ 0�� ��֮��ʾ���ļ���ͷ��string_ids��ƫ������
    u4  typeIdsSize;        //���ͱ�ʶ���б��е�Ԫ�����������Ϊ 65535
    u4  typeIdsOff;         //��� type_ids_size == 0�����ɷ�����һ����ֵļ�������������ֵΪ 0�� ��֮��ʾ���ļ���ͷ�� type_ids ���ο�ͷ��ƫ������
    u4  protoIdsSize;       //ԭ�ͣ���������ʶ���б��е�Ԫ�����������Ϊ 65535
    u4  protoIdsOff;        //��� proto_ids_size == 0�����ɷ�����һ����ֵļ�������������ֵΪ 0�� ��֮��ƫ������ʾ�ļ���ͷ�� proto_ids ���ο�ͷ��ƫ������
    u4  fieldIdsSize;       //�ֶα�ʶ���б��е�Ԫ������
    u4  fieldIdsOff;        //��� field_ids_size == 0�����ֵΪ 0�� ��֮��ƫ������ʾ�ļ���ͷ�� field_ids ���ο�ͷ��ƫ������
    u4  methodIdsSize;      //������ʶ���б��е�Ԫ������
    u4  methodIdsOff;       //��� method_ids_size == 0�����ֵΪ 0����֮��ƫ������ʾ���ļ���ͷ�� method_ids ���ο�ͷ��ƫ������
    u4  classDefsSize;      //�ඨ���б��е�Ԫ������
    u4  classDefsOff;       //��� class_defs_size == 0�����ɷ�����һ����ֵļ�������������ֵΪ 0 ����֮��ƫ������ʾ�ļ���ͷ�� class_defs ���ο�ͷ��ƫ������
    u4  dataSize;           //data ���ε����ֽ�Ϊ��λ�Ĵ�С�������� sizeof(uint) ��ż������˵�� 8 �ֽڶ��롣
    u4  dataOff;            //���ļ���ͷ�� data ���ο�ͷ��ƫ������
};

//----------������------------------

//StringIds ��
struct DexStringId {
    u4 stringDataOff;   /* �ַ�������ƫ�ƣ�Ҳ�����������и��� StringData ���ļ�ƫ��*/
};

//type_ids ��
struct DexTypeId {
    u4 descriptorIdx;    /* ָ�� DexStringId�б������ */
};

//Proto id �ֶ�
struct DexProtoId {
    u4 shortyIdx;       /* ��������+�������ͣ���д��ָ��DexStringId�б������ */
    u4 returnTypeIdx;   /* �������ͣ�ָ��DexTypeId�б������ */
    u4 parametersOff;   /* �������ͣ�ָ��DexTypeList��ƫ�� */
};

struct DexTypeItem {
    u2 typeIdx;           /* �������ͣ�ָ��DexTypeId�б������������ָ���ַ������� */
};

struct DexTypeList {
    u4 size;             /* DexTypeItem�ĸ��������������� */
    DexTypeItem list[1]; /* ָ��DexTypeItem��ʼ�� */
};

//field id ��
struct DexFieldId {
    u2 classIdx;   /* ������ͣ�ָ��DexTypeId�б������ */
    u2 typeIdx;    /* �ֶ����ͣ�ָ��DexTypeId�б������ */
    u4 nameIdx;    /* �ֶ�����ָ��DexStringId�б������ */
};

//method id ��
struct DexMethodId {
    u2 classIdx;  /* ������ͣ�ָ��DexTypeId�б������ */
    u2 protoIdx;  /* �������ͣ�ָ��DexProtoId�б������ */
    u4 nameIdx;   /* ��������  ָ��DexStringId�б������ */
};

// ����ֶ��뷽���ſ�
// ��Ļ�����Ϣ-------------------------------------------
struct DexClassDef {
    u4 classIdx;    /* ������ͣ�ָ��DexTypeId�б������ */
    u4 accessFlags; /* ���ʱ�־ */
    u4 superclassIdx;  /* �������ͣ�ָ��DexTypeId�б������ */
    u4 interfacesOff; /* �ӿڣ�ָ��DexTypeList��ƫ�� */
    u4 sourceFileIdx; /* Դ�ļ�����ָ��DexStringId�б������ */
    u4 annotationsOff; /* ע�⣬ָ��DexAnnotationsDirectoryItem�ṹ */
    u4 classDataOff;   /* ָ��DexClassData�ṹ��ƫ�� */
    u4 staticValuesOff;  /* ָ��DexEncodedArray�ṹ��ƫ�� */
};

// ��ϸ��������ֶθ����뷽������
struct DexClassDataHeader {
    u4 staticFieldsSize;  /* ��̬�ֶθ��� */
    u4 instanceFieldsSize; /* ʵ���ֶθ��� */
    u4 directMethodsSize;  /* ֱ�ӷ������� */
    u4 virtualMethodsSize; /* �鷽������ */
};

// �ֶζ���
struct DexField {
    u4 fieldIdx;    /* ָ��DexFieldId������ uleb128*/
    u4 accessFlags; /* ���ʱ�־ uleb128*/
};

// ��������
struct DexMethod {
    u4 methodIdx;   /* ָ��DexMethodId������ uleb128*/
    u4 accessFlags; /* ���ʱ�־ uleb128*/
    u4 codeOff;     /* ָ��DexCode�ṹ��ƫ�� uleb128*/
};

// ����ſ�
struct DexCode {
    u2 registersSize;   /* ʹ�õļĴ������� */
    u2 insSize;         /* �������� */
    u2 outsSize;        /* ������������ʱ��������ʹ�õļĴ��������������Լ��ĵ���ջ���룬��ѹջ���²⣩ */
    u2 triesSize;       /* Try/Catch���� */
    u4 debugInfoOff;    /* ָ�������Ϣ��ƫ�� */
    u4 insnsSize;       /* ָ���������2�ֽ�Ϊ��λ */
    u2 insns[1];        /* ָ� */
};

// ����ֶ��뷽���ſ�
struct DexClassData {
    DexClassDataHeader header; /* ָ���ֶ��뷽���ĸ��� */
    DexField* staticFields;    /* ��̬�ֶΣ�DexField�ṹ */
    DexField* instanceFields;  /* ʵ���ֶΣ�DexField�ṹ */
    DexMethod* directMethods;  /* ֱ�ӷ�����DexMethod�ṹ */
    DexMethod* virtualMethods; /* �鷽����DexMethod�ṹ */
};

//----------------������------------------------------
struct DexMapItem {
    u2 type;      /* kDexType��ͷ������ */
    u2 unused;    /* δʹ�ã������ֽڶ��� */
    u4 size;      /* ָ����Ӧ���͵ĸ��� */
    u4 offset;    /* ָ����Ӧ���͵����ݵ��ļ�ƫ�� */
};

//DEX map section
struct DexMapList {
    u4 size;               /* DexMapItem�ĸ������������ */
    DexMapItem list[1];    /* ָ��DexMapItem */
};

/* type�ֶ�Ϊһ��ö�ٳ�����ͨ���������ƺ������ж����ľ������͡� */
/* map item type codes */
enum {
    kDexTypeHeaderItem = 0x0000,
    kDexTypeStringIdItem = 0x0001,
    kDexTypeTypeIdItem = 0x0002,
    kDexTypeProtoIdItem = 0x0003,
    kDexTypeFieldIdItem = 0x0004,
    kDexTypeMethodIdItem = 0x0005,
    kDexTypeClassDefItem = 0x0006,
    kDexTypeMapList = 0x1000,
    kDexTypeTypeList = 0x1001,
    kDexTypeAnnotationSetRefList = 0x1002,
    kDexTypeAnnotationSetItem = 0x1003,
    kDexTypeClassDataItem = 0x2000,
    kDexTypeCodeItem = 0x2001,
    kDexTypeStringDataItem = 0x2002,
    kDexTypeDebugInfoItem = 0x2003,
    kDexTypeAnnotationItem = 0x2004,
    kDexTypeEncodedArrayItem = 0x2005,
    kDexTypeAnnotationsDirectoryItem = 0x2006,
};



class DexParse {
public:
    // �����ַ������ߺ���
    std::string parseString(const std::vector<uint8_t>& byteArray, size_t stringDataOff) {
        size_t offset = stringDataOff;
        unsigned int length = readUnsignedLeb128(byteArray, offset);
        return decodeString(byteArray, offset, length);
    }
    // ģ�� ULEB128 ����
    unsigned int readUnsignedLeb128(const std::vector<uint8_t>& byteArray, size_t& offset) {
        unsigned int result = 0;
        int shift = 0;
        uint8_t byteRead;

        do {
            byteRead = byteArray[offset++];
            result |= (byteRead & 0x7F) << shift;
            shift += 7;
        } while (byteRead & 0x80);  // ������ȡ��ֱ���ֽڵĸ�λΪ 0

        return result;
    }
    // ģ�� MUTF-8 ����
    std::string decodeString(const std::vector<uint8_t>& byteArray, size_t offset, size_t length) {
        std::string result;
        size_t index = offset;

        while (index < offset + length) {
            uint8_t byte = byteArray[index++];

            if (byte <= 0x7F) {
                // ���ֽ��ַ���ASCII��
                result.push_back(static_cast<char>(byte));
            }
            else if ((byte >> 5) == 0x06) {
                // ���ֽ��ַ���MUTF-8�ĵ�2���ַ���
                uint8_t byte2 = byteArray[index++];
                result.push_back(static_cast<char>(((byte & 0x1F) << 6) | (byte2 & 0x3F)));
            }
            else if ((byte >> 4) == 0x0E) {
                // ���ֽ��ַ���MUTF-8�ĵ�3���ַ���
                uint8_t byte2 = byteArray[index++];
                uint8_t byte3 = byteArray[index++];
                // �ϲ���һ�� Unicode �ַ�
                uint32_t character = ((byte & 0x0F) << 12) | ((byte2 & 0x3F) << 6) | (byte3 & 0x3F);
                result.push_back(static_cast<char>(character));  // ��ȷ���� 3 �ֽڵ��ַ�
            }
        }

        return result;
    }
    // ������������������ӡ�ַ���
    void processAndPrintString(const std::vector<uint8_t>& byteArray, size_t stringDataOff, int index) {
        // �����ַ���
        std::string decodedString = parseString(byteArray, stringDataOff);

        // ����������ַ�����ȫ�ֱ���
        decodedStrings.push_back(decodedString);

        for (char ch : decodedString) {
            if (ch == '\n') {
                printf("\\n");
            }
            else {
                printf("%c", ch);
            }
        }
        printf("\n");
    }
    void ParseDexHeader(FILE* fp);
    void ParseStringIds(FILE* fp);
    void ParseTypeIds(FILE* fp);
    void ParseProtoIds(FILE* fp);
    void ParseDexFieldIds(FILE* fp);
    void ParseDexMethodId(FILE* fp);
    void ParseDexClass(FILE* fp);
private:
    std::vector<std::string> decodedStrings;
    std::vector<std::string> typeStrings;
    std::vector<std::string> protoStrings;
};
