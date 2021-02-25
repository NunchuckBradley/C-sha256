// code influenced from bitcoin source code

#ifndef UINT_CUSTOM_H
#define UINT_CUSTOM_H

#include <cstring>
#include <sstream>

//#include <cryptopp/filters.h>
//#include <cryptopp/hex.h>


template<unsigned int BITS>
class uint256 {
protected:
    static constexpr int WIDTH = BITS / 8;
    uint8_t m_data[WIDTH];
public:

//    uint256(unsigned char* data) {
//        int i = 0;
//        while(i < WIDTH) {
//            m_data[i] = data[i];
//        }
//    }
//    uint8_t & operator [](int i) {return m_data[i];}
    uint8_t operator [](int i) const    {return m_data[i];}
    uint8_t & operator [](int i) {return m_data[i];}

    uint8_t & at(int i) {return m_data[i];}

    void operator = (const unsigned int num) {
        memcpy(&m_data, &num, WIDTH);
//        reverseOrder();
    }

    void operator = (unsigned char* data) {
        memcpy(&m_data, data, WIDTH);
//        reverseOrder();
    }

    void combine(uint256<256> comb1, uint256<256> comb2) {
        if (BITS == 512) {
            int i = 0;
            while(i < WIDTH / 2) {
                m_data[i] = comb2[i];
                m_data[WIDTH/2+i] = comb1[i];
                i++;
            }
//            memcpy(&m_data, &comb1, WIDTH/2);
//            memcpy(&m_data+WIDTH/2, &comb2, WIDTH/2);
        }
    }

    int length() {return sizeof(m_data);}

    unsigned char asChar() {
        unsigned char tmp;


        memset(&tmp, 0, WIDTH);
        memcpy(&tmp, &m_data, WIDTH);

//        unsigned char* tmp2 = (unsigned char*)tmp;
//        int i = 0;
//        while(i < WIDTH) {
//            tmp[i] = m_data[WIDTH - 1 - i];
//            i++;
//        }

//        memset(out, WIDTH);
//        memcpy(out, &tmp, WIDTH);
//        out = tmp;

        return tmp;
    }

//    void operator = (const CryptoPP::byte* bytes) {
//        memcpy(&m_data, bytes, WIDTH);
//    }

//    void addBytes(const CryptoPP::byte* bytes)
//    {
//        memcpy(m_data, bytes, WIDTH);
//        std::cout << "adding bytes to 256int" << std::endl;
//        CryptoPP::byte* edata = (CryptoPP::byte*)bytes;
//        int i = 0;
//        while(i < WIDTH) {
//            m_data[i] = bytes[i];
//            i++;
//        }
//    }

    void reverseOrder() {
        // swap byte order
        int e = 0;
        int s = WIDTH-1;
        while (s > e) {
            uint8_t tmp = m_data[s];
            m_data[s] = m_data[e];
            m_data[e] = tmp;
            s--;
            e++;
        }
    }

    static uint8_t reverse(uint8_t* data) {
        uint8_t tmp;
        uint8_t *pnt = &tmp;
        int i = 0;
        while(i < WIDTH) {
            pnt[i] = data[WIDTH - 1 - i];
            i++;
        }
        return tmp;
    }

    // https://stackoverflow.com/questions/8406148/how-to-do-reverse-memcmp
    static int reversememcmp(const void *s1, const void *s2, size_t n)
    {
        if(n == 0)
            return 0;

        // Grab pointers to the end and walk backwards
        const unsigned char *p1 = (const unsigned char*)s1 + n - 1;
        const unsigned char *p2 = (const unsigned char*)s2 + n - 1;

        while(n > 0)
        {
            // If the current characters differ, return an appropriately signed
            // value; otherwise, keep searching backwards
            if(*p1 != *p2)
                return *p1 - *p2;
            p1--;
            p2--;
            n--;
        }

        return 0;
    }

    inline int Compare(const uint256& other) const {
        return reversememcmp(m_data, other.m_data, sizeof(m_data));
//        return memcmp((uint8_t*)reverse((uint8_t*)m_data), (uint8_t*)reverse((uint8_t*)other.m_data), sizeof(m_data));
    }

    friend inline bool operator==(const uint256& a, const uint256& b) { return a.Compare(b) == 0; }
    friend inline bool operator!=(const uint256& a, const uint256& b) { return a.Compare(b) != 0; }
    friend inline bool operator<(const uint256& a, const uint256& b) { return a.Compare(b) < 0; }
    friend inline bool operator>(const uint256& a, const uint256& b) { return a.Compare(b) > 0; }

    void write32BitAt(int pos, unsigned int val) {
        for(int i = 0; i < 4; i++) {
            m_data[pos+i] = (val << (i*8)) >> 24;
        }
    }

    void shiftLeft(int shift) {
        for(int s = 0; s < shift; s++) {
            for(int i = 0; i < WIDTH-1; i++) {
                m_data[i] = m_data[i+1];
            }
            m_data[WIDTH-1] = 0;
        }
    }

    std::string decToHex(int dec) {
        std::stringstream ss;
        ss<< std::hex << dec; // int decimal_value
        std::string res ( ss.str() );
        return res;
    }
    unsigned int stringHexToInt(std::string str) {
        unsigned int x;
        std::stringstream ss;
        ss << std::hex << str;
        ss >> x;
        return x;
    }

    std::string getHex(bool bigendian = true) {
        std::string out;
        for (int i = 0; i < WIDTH; ++i) {
            int index;
            if (bigendian) {
                index = WIDTH - 1 - i;
            } else {
                index = i;
            }
            // for 'empty' uint8
            if (m_data[index] == 00) {
                out += '0';
                out += '0';
            } else {
                // for almost 'empty' uint8
                // now handled by decToHex <- no
                if (m_data[index] < 16) {
                    out += '0';
                }
                out += decToHex(m_data[index]);
            }
        }
        return out;
    }

    void setHex(const char* psz)
    {
        if (sizeof(psz) > 0) {
            int i = 0;
            while (i < WIDTH) {
                std::string tmp = std::string() + psz[i*2] + psz[(i*2)+1];
    //            std::cout << "comverting " << i << "/" << WIDTH - 1 - i << " : " << tmp << " to " << Crypto::stringHexToInt(tmp) << std::endl;
                m_data[WIDTH - 1 - i] = stringHexToInt(tmp);
                i++;
            }
        }

    }

    void setHex(const std::string& str)
    {
        setHex(str.c_str());
    }
    std::string toString(){
        return getHex();
    }

    void writeData(int i, uint8_t data) {
        m_data[i] = data;
    }

    void clear() {
        delete[] m_data;
    }
};

#endif // UINT_CUSTOM_H
