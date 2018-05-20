#include <stdio.h>
#include <string.h>
#include <malloc.h>
#define FIXED_TABLES
#include "aes/aescpp.h"

#define  BLOCK_LEN  16

#include <string>
using namespace std;

bool SaveToFile(char* filePath, std::string &str);

// 加密文件的头，避免重复加密
char g_szEnFlag[] = "EncryProtect";
// 头部留16个空间，可以用于扩展
int  g_nEnFlagSize = 16;

// 加密接口
bool encfile(char* filePath,const char * EncryKey,int EncryKeyLen)
{
	bool bRet = false;
	FILE* pFile = fopen(filePath,"rb");
	do
	{
		if (!pFile)
			break;
		fseek(pFile, 0, SEEK_END);
		int nLen = ftell(pFile);
		fseek(pFile, 0, SEEK_SET);
		int nBlockFitSize = (nLen/BLOCK_SIZE)*BLOCK_SIZE + BLOCK_SIZE;
		char *pData = (char*)malloc(nBlockFitSize);
		memset(pData,0,nBlockFitSize);
		if (!pData)
			break;
		fread(pData,1,nLen,pFile);

		// 是否已经是加密文件
		int nRet = memcmp(pData,g_szEnFlag,strlen(g_szEnFlag));
		if(nRet == 0)
		{
			free(pData);
			break;
		}
			
		// 加密文件
		aes_ctx cx = {0};
		cx.n_blk = BLOCK_SIZE; 
		cx.n_rnd = 0;
		aes_enc_key((const unsigned char*)EncryKey,EncryKeyLen,&cx);
		string str;
		str.append(g_szEnFlag,g_nEnFlagSize);
		unsigned char buf[BLOCK_SIZE] = {0};
		for (int i = 0; i<nBlockFitSize; i+=BLOCK_SIZE )
		{
			aes_enc_blk((const unsigned char*)pData+i,buf,&cx);
			str.append((char*)buf,BLOCK_SIZE);
		}		
		char szPath[256] = {0};
		strcpy(szPath,filePath);
		strcat(szPath,".Encry");
		bRet = SaveToFile(szPath, str);
	}while(0);
	fclose(pFile);
	return bRet;
}

bool decryFile(const char* pFilePath,const char* key,const int keyLen)
{
	bool bRet = false;
	FILE* pFile = fopen(pFilePath,"rb");
	do
	{
		if (!pFile)
			break;
		fseek(pFile, 0, SEEK_END);
		int nLen = ftell(pFile);
		fseek(pFile, 0, SEEK_SET);
		char *pFileData = (char*)malloc(nLen);
		memset(pFileData,0,nLen);
		if (!pFileData)
			break;
		fread(pFileData,1,nLen,pFile);
		// 是否已经是加密文件
		int nEncryFlagLen = strlen(g_szEnFlag);
		int nRet = memcmp(pFileData,g_szEnFlag,nEncryFlagLen);
		if(nRet != 0)
		{
			free(pFileData);
			break;
		}
		// 解密文件内容
		aes_ctx cx = {0};
		cx.n_blk = BLOCK_SIZE; 
		cx.n_rnd = 0;
		aes_dec_key((const unsigned char*)key,keyLen,&cx);
		string strDecry;
		unsigned char DeBuf[BLOCK_LEN] = {0};
		char *pDataBuf = pFileData + g_nEnFlagSize;
		for (int i= 0;i<nLen-g_nEnFlagSize;i+=BLOCK_SIZE)
		{
			aes_dec_blk((const unsigned char*)pDataBuf+i,DeBuf,&cx);
			strDecry.append((char*)DeBuf,BLOCK_SIZE);
		}
		char szPath[256] = {0};
		strcpy(szPath,pFilePath);
		char* pFind = strstr(szPath,".");
		if (pFind)
		{
			pFind[0] = '\0';
		}
		strcat(szPath,".Decry");
		bRet = SaveToFile(szPath, strDecry);
	}while(0);
	fclose(pFile);
	return bRet;
}

bool SaveToFile(char* filePath, std::string &str)
{
	bool bRet = false;
	FILE* pFileWrite = fopen(filePath,"wb");
	if (pFileWrite)
	{
		int nSize = str.size();
		int nRet = fwrite(str.c_str(),1,nSize,pFileWrite);
		if (nSize == bRet)
			bRet = true;
	}
	fclose(pFileWrite);
	return bRet;
}

void StringDemo()
{
	char Key[16] = "yahvdfbh";
	char* inWord = "Hello,北京！";


	int DataLen = strlen(inWord);

	int nBlockFitSize  = 0;
	if ((DataLen%BLOCK_SIZE) == 0)
	{
		nBlockFitSize = DataLen;
	}
	else
	{
		nBlockFitSize = ((DataLen/BLOCK_SIZE)+1) * BLOCK_SIZE;
	}

	AESclass encryption;

	char* pTextData = (char*)malloc(nBlockFitSize);
	memset(pTextData,0,nBlockFitSize);
	memcpy(pTextData,inWord,DataLen);

	int nRet = encryption.enc_key((const unsigned char*)Key,16);
	string str;
	unsigned char enBuf[BLOCK_LEN] = {0};
	for (int i=0; i< nBlockFitSize ; i+=BLOCK_SIZE)
	{
		char buf[BLOCK_SIZE] = {0};
		memcpy(buf,pTextData+i,BLOCK_SIZE);
		encryption.enc_blk((unsigned char*)buf,enBuf);
		str.append((char*)buf,BLOCK_SIZE);
	}


	AESclass decryption;
	decryption.dec_key((const unsigned char*)Key,16);
	int nEndataLen = str.size();
	string strDecry;
	unsigned char DeBuf[BLOCK_LEN] = {0};
	const char* pEncryData = str.data();
	for (int i=0;i<nEndataLen;i+=BLOCK_SIZE)
	{
		decryption.dec_blk((const unsigned char*)pEncryData+i,DeBuf); 
		strDecry.append((char*)DeBuf,BLOCK_SIZE);
	}
}

int main()
{
	//StringDemo();
	encfile("Data.txt","fhjkhkjd",256/8);
	decryFile("Data.txt.Encry","fhjkhkjd",256/8);
	return 0;
}

