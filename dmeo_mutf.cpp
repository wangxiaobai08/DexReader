#include <iostream>
#include <vector>
#include <string>

// ģ�� ULEB128 ����
void writeUnsignedLeb128(std::vector<uint8_t>& byteArray, unsigned int value) {
    while (value > 0x7F) {
        byteArray.push_back(static_cast<uint8_t>(value | 0x80));  // ���ø�λΪ 1����ʾ���и����ֽ�
        value >>= 7;
    }
    byteArray.push_back(static_cast<uint8_t>(value));  // ���һ���ֽڵĸ�λΪ 0
}

// ģ�� MUTF-8 ����
void encodeString(std::vector<uint8_t>& byteArray, const std::string& str) {
    for (char ch : str) {
        unsigned char byte = static_cast<unsigned char>(ch);
        if (byte <= 0x7F) {
            byteArray.push_back(byte);  // ���ֽ��ַ�
        }
        else if ((byte >> 5) == 0x06) {
            // ���ֽ��ַ���MUTF-8�ĵ�2���ַ���
            byteArray.push_back(0xC0 | (byte >> 6));
            byteArray.push_back(0x80 | (byte & 0x3F));
        }
        else if ((byte >> 4) == 0x0E) {
            // ���ֽ��ַ���MUTF-8�ĵ�3���ַ���
            byteArray.push_back(0xE0 | (byte >> 12));
            byteArray.push_back(0x80 | ((byte >> 6) & 0x3F));
            byteArray.push_back(0x80 | (byte & 0x3F));
        }
    }
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

// ���� MUTF-8 ����
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

//int main() {
//    // 1. �û������ַ���
//    std::string inputStr;
//    std::cout << "������Ҫ������ַ���: ";
//    std::getline(std::cin, inputStr);  // �û������ַ���
//
//    // 2. �������
//    std::vector<uint8_t> byteArray;
//    // ULEB128 ���볤��
//    writeUnsignedLeb128(byteArray, inputStr.size());
//    // MUTF-8 �����ַ���
//    encodeString(byteArray, inputStr);
//
//    // ��ӡ�������ֽ���
//    std::cout << "�������ֽ���: ";
//    for (uint8_t byte : byteArray) {
//        std::cout << std::hex << (int)byte << " ";
//    }
//    std::cout << std::dec << std::endl;  // ���������ʮ����
//
//    // 3. �������
//    size_t offset = 0;
//    unsigned int length = readUnsignedLeb128(byteArray, offset);  // ��ȡ�ַ�������
//    std::cout << "ULEB128 �������ַ�������: " << length << std::endl; // ��ӡ ULEB128 �������ַ�������
//    std::string decodedString = decodeString(byteArray, offset, length);  // �����ַ���
//
//    // ��ӡ�������ַ�����
//    std::cout << "�������ַ�����: " << decodedString.size() << std::endl;
//
//    // 4. ���������
//    std::cout << "�������ַ���: " << decodedString << std::endl;
//
//    return 0;
//}
