typedef unsigned char byte;

struct word
{
	byte wordKey[4];
};

class AES
{
public:
	AES(){
		initRcon();
	};
	// ~AES();
	void setCipherKey(char * key, int len);
	void setPlainText(char * plain, int len);
	void setCripherText(char * cripher, int len);
	//
	void showWord(word w[], int len);
	void showMesage();
	void encryption();
	void processEncryption();
	void decryption();
	void processDecryption();
	
	void keyExpansion(byte key[], word w[]);
	word rotWord(word w);
	word subWord(word w);
	word wordXOR(word w1, word w2);
	//functions in encryption and decryption
	void addRoundKey(word in[], int round);
	void subByte(word in[]);
	void shiftRows(word in[]);
	void mixColumn(word in[]);
	byte GFMultiplyByte(byte L, byte R);
	void invShiftRows(word in[]);
	void invSubByte(word in[]);
	void invMixColumn(word in[]);
	void initRcon();

	char * getPlainText(char * plain, int * retlen);
	char * getCripherText(char * massage, int * retlen);

private:
	byte * plain;
	byte * cipher;
	byte * decipher;

	byte cipherKey[16];
	word plainText[4];
	word cipherText[4];
	word deCipherText[4];
	
    static const int Nb=4, Nk=4, Nr=14;
	word Rcon[15];
	word wordKey[60];

	static const byte SBox[16][16];
	static const byte invSBox[16][16];
	static const byte mixColumnMatrix[4][4];
	static const byte invmixColumnMatrix[4][4];
};
